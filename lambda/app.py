from chalice import Chalice, Response
from botocore.config import Config as bc_Config
from botocore.exceptions import ClientError
import os
import json

from urllib.parse import urlparse, quote_plus

from rain_api_core.general_util import get_log
from rain_api_core.urs_util import get_urs_url, do_login, user_in_group
from rain_api_core.aws_util import get_yaml_file, get_s3_resource, get_role_session, get_role_creds, check_in_region_request
from rain_api_core.view_util import get_html_body, get_cookie_vars, make_set_cookie_headers_jwt
from rain_api_core.egress_util import get_presigned_url, process_varargs, check_private_bucket, check_public_bucket

app = Chalice(app_name='egress-lambda')
log = get_log()
conf_bucket = os.getenv('CONFIG_BUCKET', "rain-t-config")

# Here's a lifetime-of lambda cache of these values:
bucket_map_file = os.getenv('BUCKET_MAP_FILE', 'bucket_map.yaml')
b_map = None
public_buckets_file = os.getenv('PUBLIC_BUCKETS_FILE', None)
public_buckets = None
private_buckets_file = os.getenv('PRIVATE_BUCKETS_FILE', None)
private_buckets = None
s3_resource = get_s3_resource()

STAGE = os.getenv('STAGE_NAME', 'DEV')
header_map = {'date':           'Date',
              'last-modified':  'Last-Modified',
              'accept-ranges':  'Accept-Ranges',
              'etag':           'ETag',
              'content-type':   'Content-Type',
              'content-length': 'Content-Length'}


def restore_bucket_vars():

    global b_map                                                                       #pylint: disable=global-statement
    global public_buckets                                                              #pylint: disable=global-statement
    global private_buckets                                                             #pylint: disable=global-statement

    log.debug('conf bucket: {}, bucket_map_file: {}, ' +
              'public_buckets_file: {}, private buckets file: {}'.format(conf_bucket,
                                                                         bucket_map_file,
                                                                         public_buckets_file,
                                                                         private_buckets_file))
    if b_map is None or public_buckets is None or private_buckets is None:
        log.info('downloading various bucket configs from {}: bucketmapfile: {}, ' +
                 'public buckets file: {}, private buckets file: {}'.format(conf_bucket,
                                                                            bucket_map_file,
                                                                            public_buckets_file,
                                                                            private_buckets_file))
        b_map = get_yaml_file(conf_bucket, bucket_map_file, s3_resource)
        log.debug('bucket map: {}'.format(b_map))
        if public_buckets_file:
            log.debug('fetching public buckets yaml file: {}'.format(public_buckets_file))
            public_buckets = get_yaml_file(conf_bucket, public_buckets_file, s3_resource)
        else:
            public_buckets = {}
        if private_buckets_file:
            private_buckets = get_yaml_file(conf_bucket, private_buckets_file, s3_resource)
        else:
            private_buckets = {}
    else:
        log.info('reusing old bucket configs')


def do_auth_and_return(ctxt):

    log.debug('context: {}'.format(ctxt))
    here = ctxt['path']
    if os.getenv('DOMAIN_NAME'):
        # Pop STAGE value off the request if we have a custom domain
        here = '/'.join([""]+here.split('/')[2:]) if here.startswith('/{}/'.format(STAGE)) else here
    log.info("here will be {0}".format(here))
    redirect_here = quote_plus(here)
    urs_url = get_urs_url(ctxt, redirect_here)
    log.info("Redirecting for auth: {0}".format(urs_url))
    return Response(body='', status_code=302, headers={'Location': urs_url})


def make_redriect(to_url, headers=None, status_code=301):
    if headers is None:
        headers = {}
    headers['Location'] = to_url
    log.debug('to_url: {}'.format(to_url))
    log.debug('headers: {}'.format(headers))
    return Response(body='', headers=headers, status_code=status_code)


def make_html_response(t_vars: dict, hdrs: dict, status_code: int=200, template_file: str='root.html'):
    template_vars = {'STAGE': STAGE if not os.getenv('DOMAIN_NAME') else None, 'status_code': status_code}
    template_vars.update(t_vars)

    headers = {'Content-Type': 'text/html'}
    headers.update(hdrs)

    return Response(body=get_html_body(template_vars, template_file), status_code=status_code, headers=headers)


def get_bcconfig(user_id: str) -> dict:
    bcconfig = {"user_agent": "Thin Egress App for userid={0}".format(user_id),
                "s3": {"addressing_style": "path"},
                "connect_timeout": 600,
                "read_timeout": 600,
                "retries": {"max_attempts": 10}}

    if os.getenv('S3_SIGNATURE_VERSION'):
        bcconfig['signature_version'] = os.getenv('S3_SIGNATURE_VERSION')

    return bcconfig


def get_bucket_region(session, bucketname) ->str:
    # Figure out bucket region
    params = {}
    try:
        bucket_region = session.client('s3', **params).get_bucket_location(Bucket=bucketname)['LocationConstraint']
        bucket_region = 'us-east-1' if not bucket_region else bucket_region
        log.debug("bucket {0} is in region {1}".format(bucketname, bucket_region))
    except ClientError as e:
        # We hit here if the download role cannot access a bucket, or if it doesn't exist
        log.error("Could not access download bucket {0}: {1}".format(bucketname, e))
        raise

    return bucket_region

def try_download_from_bucket(bucket, filename, user_profile):

    # Attempt to pull userid from profile
    user_id = None
    if isinstance(user_profile, dict):
        if 'urs-user-id' in user_profile :
            user_id = user_profile['urs-user-id']
        elif 'uid' in user_profile:
            user_id = user_profile['uid']
    log.info("User Id for download is {0}".format(user_id))

    is_in_region = check_in_region_request(app.current_request.context['identity']['sourceIp'])
    creds = get_role_creds(user_id, is_in_region)

    session = get_role_session(creds=creds, user_id=user_id)

    try:
        bucket_region = get_bucket_region(session, bucket)
    except ClientError as e:
        log.error(f'ClientError while {user_id} tried downloading {bucket}/{filename}: {e}')
        template_vars = {'contentstring': 'There was a problem accessing download data.', 'title': 'Data Not Available'}
        headers = {}
        return make_html_response(template_vars, headers, 500, 'error.html')

    log.debug('this region: {}'.format(os.getenv('AWS_DEFAULT_REGION', 'env var doesnt exist')))
    if bucket_region != os.getenv('AWS_DEFAULT_REGION'):
        log.warning("bucket {0} is in region {1}, we are in region {2}! " +
                    "This is double egress in Proxy mode!".format(bucket,
                                                                  bucket_region,
                                                                  os.getenv('AWS_DEFAULT_REGION')))
    params = {}
    # now that we know where the bucket is, connect in THAT region
    params['config'] = bc_Config(**get_bcconfig(user_id))
    client = session.client('s3', bucket_region, **params)

    log.info("Attempting to download s3://{0}/{1}".format(bucket, filename))

    try:
        # Make sure this file exists, don't ACTUALLY download
        range_header = get_range_header_val()
        if not range_header:
            client.get_object(Bucket=bucket, Key=filename)
            redirheaders = {}
        else:
            client.get_object(Bucket=bucket, Key=filename, Range=range_header)
            redirheaders = {'Range': range_header}

        # Generate URL
        presigned_url = get_presigned_url(creds, bucket, filename, bucket_region, 24 * 3600, user_id)
        s3_host = urlparse(presigned_url).netloc
        log.debug("Presigned URL host was {0}".format(s3_host))

        log.info("Using REDIRECT because no PROXY in egresslambda")
        return make_redriect(presigned_url, redirheaders, 303)

    except ClientError as e:
        log.warning("Could not download s3://{0}/{1}: {2}".format(bucket, filename, e))

        # Watch for bad range request:
        if e.response['ResponseMetadata']['HTTPStatusCode'] == 416:
            return Response(body='Invalid Range', status_code=416, headers={})

        template_vars = {'contentstring': 'Could not find requested data.', 'title': 'Data Not Available'}
        headers = {}
        return make_html_response(template_vars, headers, 404, 'error.html')


def get_jwt_field(cookievar: dict, fieldname: str):
    if os.getenv('JWT_COOKIENAME', 'asf-urs') in cookievar:
        if fieldname in cookievar[os.getenv('JWT_COOKIENAME', 'asf-urs')]:
            return cookievar[os.getenv('JWT_COOKIENAME', 'asf-urs')][fieldname]

    return None


@app.route('/')
def root():

    user_profile = False
    template_vars = {'title': 'Welcome'}

    cookievars = get_cookie_vars(app.current_request.headers)
    if cookievars:
        if os.getenv('JWT_COOKIENAME', 'asf-urs') in cookievars:
            # We have a JWT cookie
            user_profile = cookievars[os.getenv('JWT_COOKIENAME', 'asf-urs')]

    if user_profile:
        if os.getenv('MATURITY') == 'DEV':
            template_vars['profile'] = user_profile
    else:
        template_vars['URS_URL'] = get_urs_url(app.current_request.context)

    headers = {'Content-Type': 'text/html'}
    return make_html_response(template_vars, headers, 200, 'root.html')


@app.route('/logout')
def logout():

    cookievars = get_cookie_vars(app.current_request.headers)
    template_vars = {'title': 'Logged Out', 'URS_URL': get_urs_url(app.current_request.context)}

    if os.getenv('JWT_COOKIENAME', 'asf-urs') in cookievars:

        template_vars['contentstring'] = 'You are logged out.'
    else:
        template_vars['contentstring'] = 'No active login found.'

    headers = {
        'Content-Type': 'text/html',
    }

    headers.update(make_set_cookie_headers_jwt({}, 'Thu, 01 Jan 1970 00:00:00 GMT', os.getenv('COOKIE_DOMAIN', '')))
    return make_html_response(template_vars, headers, 200, 'root.html')


@app.route('/login')
def login():
    status_code, template_vars, headers = do_login(app.current_request.query_params, app.current_request.context, os.getenv('COOKIE_DOMAIN', ''))
    if status_code == 301:
        return Response(body='', status_code=status_code, headers=headers)

    return make_html_response(template_vars, headers, status_code, 'error.html')


@app.route('/version')
def version():
    return json.dumps({'version_id': '<BUILD_ID>'})


def get_range_header_val():

    if 'Range' in app.current_request.headers:
        return app.current_request.headers['Range']
    if 'range' in app.current_request.headers:
        return app.current_request.headers['range']
    return None


def get_data_dl_s3_client():

    user_id = get_jwt_field(get_cookie_vars(app.current_request.headers), 'urs-user-id')

    session = get_role_session(user_id=user_id)
    params = {}

    params['config'] = bc_Config(**get_bcconfig(user_id))
    client = session.client('s3', **params)
    return client


def try_download_head(bucket, filename):

    client = get_data_dl_s3_client()
    # Check for range request
    range_header = get_range_header_val()
    try:
        if not range_header:
            download = client.get_object(Bucket=bucket, Key=filename)
        else:
            log.info("Downloading range {0}".format(range_header))
            download = client.get_object(Bucket=bucket, Key=filename, Range=range_header)
    except ClientError as e:
        log.warning("Could get head for s3://{0}/{1}: {2}".format(bucket, filename, e))
        template_vars = {'contentstring': 'File not found',
                         'title': 'File not found'}
        headers = {}
        return make_html_response(template_vars, headers, 404, 'error.html')
    log.debug(download)

    response_headers = {'Content-Type': download['ContentType']}
    for header in download['ResponseMetadata']['HTTPHeaders']:
        name = header_map[header] if header in header_map else header
        value = download['ResponseMetadata']['HTTPHeaders'][header] if header != 'server' else 'egress'
        log.debug("setting header {0} to {1}.".format(name, value))
        response_headers[name] = value

    # Try Redirecting to HEAD. There should be a better way.
    user_id = get_jwt_field(get_cookie_vars(app.current_request.headers), 'urs-user-id')

    # Generate URL
    creds = get_role_creds(user_id=user_id)
    bucket_region = client.get_bucket_location(Bucket=bucket)['LocationConstraint']
    bucket_region = 'us-east-1' if not bucket_region else bucket_region
    presigned_url = get_presigned_url(creds, bucket, filename, bucket_region, 24 * 3600, user_id, 'HEAD')
    s3_host = urlparse(presigned_url).netloc

    # Return a redirect to a HEAD
    log.debug("Presigned HEAD URL host was {0}".format(s3_host))
    return make_redriect(presigned_url, {}, 303)


# Attempt to validate HEAD request
@app.route('/{proxy+}', methods=['HEAD'])
def dynamic_url_head():

    log.debug('attempting to HEAD a thing')
    restore_bucket_vars()

    if 'proxy' in app.current_request.uri_params:
        path, bucket, filename = process_varargs(app.current_request.uri_params['proxy'], b_map)

        process_results = 'path: {}, bucket: {}, filename:{}'.format(path, bucket, filename)
        log.debug(process_results)

        if not bucket:
            template_vars = {'contentstring': 'Bucket not available',
                             'title': 'Bucket not available'}
            headers = {}
            return make_html_response(template_vars, headers, 404, 'error.html')

        return try_download_head(bucket, filename)
    return Response(body='HEAD failed', headers={}, status_code=400)


@app.route('/{proxy+}', methods=['GET'])
def dynamic_url():

    log.debug('attempting to GET a thing')
    restore_bucket_vars()

    if 'proxy' in app.current_request.uri_params:
        path, bucket, filename = process_varargs(app.current_request.uri_params['proxy'], b_map)
        log.debug('path, bucket, filename: {}'.format(( path, bucket, filename)))
        if not bucket:
            template_vars = {'contentstring': 'File not found', 'title': 'File not found'}
            headers = {}
            return make_html_response(template_vars, headers, 404, 'error.html')
    else:
        path, bucket, filename = (None, None, None)

    cookievars = get_cookie_vars(app.current_request.headers)
    user_profile = None
    if cookievars:
        log.debug('cookievars: {}'.format(cookievars))
        if os.getenv('JWT_COOKIENAME', 'asf-urs') in cookievars:
            # this means our cookie is a jwt and we don't need to go digging in the session db
            user_profile = cookievars[os.getenv('JWT_COOKIENAME', 'asf-urs')]
        else:
            log.warning('jwt cookie not found')
            # Not kicking user out just yet. We might be dealing with a public bucket

    # Check for public bucket
    if check_public_bucket(bucket, public_buckets, b_map):
        log.debug("Accessing public bucket {0}".format(path))
    elif not user_profile:
        return do_auth_and_return(app.current_request.context)

    # Check that the bucket is either NOT private, or user belongs to that group
    private_check = check_private_bucket(bucket, private_buckets, b_map)  # NOTE: Is an optimization attempt worth it
                                                                          # if we're asking for a public file and we
                                                                          # omit this check?
    log.debug('private check: {}'.format(private_check))
    u_in_g, new_user_profile = user_in_group(private_check, cookievars, user_profile, False)
    if new_user_profile and new_user_profile != user_profile:
        log.debug("Profile was mutated from {0} => {1}".format(user_profile,new_user_profile))
        user_profile = new_user_profile
    log.debug('user_in_group: {}'.format(u_in_g))
    if private_check and not u_in_g:
        template_vars = {'contentstring': 'This data is not currently available.', 'title': 'Could not access data'}
        headers = {}
        return make_html_response(template_vars, headers, 403, 'error.html')

    if not filename:
        log.warning("Request was made to directory listing instead of object: {0}".format(path))

        template_vars = {'contentstring': 'Request does not appear to be valid.', 'title': 'Request Not Serviceable'}
        headers = {}
        return make_html_response(template_vars, headers, 404, 'error.html')

    return try_download_from_bucket(bucket, filename, user_profile)


@app.route('/profile')
def profile():
    return Response(body='Profile not available.',
                    status_code=200, headers={})
