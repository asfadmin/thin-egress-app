from chalice import Chalice, Response
from botocore.config import Config as bc_Config
from botocore.exceptions import ClientError
import os
from urllib.parse import urlparse, quote_plus


from common import get_log, do_auth, get_yaml_file, process_varargs, \
    check_private_bucket, check_public_bucket, user_in_group, \
    header_map, get_presigned_url, get_html_body, \
    get_profile, get_urs_url, STAGE, get_session, delete_session, get_cookie_expiration_date_str, get_cookie_vars, \
    get_role_session, get_role_creds

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


def restore_bucket_vars():

    global b_map                                                                       #pylint: disable=global-statement
    global public_buckets                                                              #pylint: disable=global-statement
    global private_buckets                                                             #pylint: disable=global-statement

    log.debug(
        'conf bucket: {}, bucket_map_file: {}, public_buckets_file: {}, private buckets file: {}'.format(conf_bucket,
                                                                                                         bucket_map_file,
                                                                                                         public_buckets_file,
                                                                                                         private_buckets_file))
    if b_map is None or public_buckets is None or private_buckets is None:
        log.info('downloading various bucket configs from {}: bucketmapfile: {}, public buckets file: {}, private buckets file: {}'.format(conf_bucket, bucket_map_file, public_buckets_file, private_buckets_file))
        b_map = get_yaml_file(conf_bucket, bucket_map_file)
        log.debug('bucket map: {}'.format(b_map))
        if public_buckets_file:
            log.debug('fetching public buckets yaml file: {}'.format(public_buckets_file))
            public_buckets = get_yaml_file(conf_bucket, public_buckets_file)
        else:
            public_buckets = {}
        if private_buckets_file:
            private_buckets = get_yaml_file(conf_bucket, private_buckets_file)
        else:
            private_buckets = {}
    else:
        log.info('reusing old bucket configs')


def get_endpoint():

    return 'https://{}/{}/'.format(app.current_request.context['domainName'], STAGE)


def do_auth_and_return(ctxt):

    log.debug('context: {}'.format(ctxt))
    here = ctxt['path']
    log.info("here will be {0}".format(here))
    redirect_here = quote_plus(here)
    URS_URL = get_urs_url(ctxt, redirect_here)
    log.info("Redirecting for auth: {0}".format(URS_URL))
    return Response(body='', status_code=302, headers={'Location': URS_URL})


def make_redriect(to_url, headers=None, status_code=301):
    if headers is None:
        headers = {}
    headers['Location'] = to_url
    log.debug('to_url: {}'.format(to_url))
    log.debug('headers: {}'.format(headers))
    return Response(body='', headers=headers, status_code=status_code)


def make_html_response(t_vars:dict, hdrs:dict, status_code:int=200, template_file:str='root.html'):
    template_vars = {'STAGE': STAGE, 'status_code': status_code}
    template_vars.update(t_vars)

    headers = {'Content-Type': 'text/html'}
    headers.update(hdrs)

    return Response(body=get_html_body(template_vars, template_file), status_code=status_code, headers=headers)


def try_download_from_bucket(bucket, filename, user_profile):
    user_id = user_profile['uid'] if isinstance(user_profile, dict) and 'uid' in user_profile else None
    creds = get_role_creds(user_id=user_id)
    session = get_role_session(creds=creds, user_id=user_id)

    params = {}

    BCCONFIG = {"user_agent": "RAIN Egress App for userid={0}".format(user_id),
                "s3": {"addressing_style": "path"},
                "connect_timeout": 600,
                "read_timeout": 600,
                "retries": {"max_attempts": 10}}

    if os.getenv('S3_SIGNATURE_VERSION'):
        BCCONFIG['signature_version'] = os.getenv('S3_SIGNATURE_VERSION')

    # Figure out bucket region
    try:
        bucket_region = session.client('s3', **params).get_bucket_location(Bucket=bucket)['LocationConstraint']
        bucket_region = 'us-east-1' if not bucket_region else bucket_region
        log.debug("bucket {0} is in region {1}".format(bucket, bucket_region))
    except ClientError as e:
        # We hit here if the download role cannot access a bucket, or if it doesn't exist
        log.error("Coud not access download bucket {0}: {1}".format(bucket, e))

        template_vars = {'contentstring': 'There was a problem accessing download data.', 'title': 'Data Not Available'}
        headers = {}
        return make_html_response(template_vars, headers, 500, 'error.html')

    log.debug('this region: {}'.format(os.getenv('AWS_DEFAULT_REGION', 'env var doesnt exist')))
    if bucket_region != os.getenv('AWS_DEFAULT_REGION'):
        log.warning(
            "bucket {0} is in region {1}, we are in region {2}! This is double egress in Proxy mode!".format(bucket,
                                                                                                             bucket_region,
                                                                                                             os.getenv(
                                                                                                                 'AWS_DEFAULT_REGION')))

    # now that we know where the bucket is, connect in THAT region
    params['config'] = bc_Config(**BCCONFIG)
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


@app.route('/')
def root():

    user_profile = False
    template_vars = {'title': 'Welcome'}

    cookievars = get_cookie_vars(app.current_request.headers)
    if cookievars:
        user_profile = get_session(cookievars['urs-user-id'], cookievars['urs-access-token'])

    if user_profile:
        if os.getenv('MATURITY', '') == 'DEV':
            template_vars['profile'] = user_profile
    else:
        template_vars['URS_URL'] = get_urs_url(app.current_request.context)

    headers = {'Content-Type': 'text/html'}
    return make_html_response(template_vars, headers, 200, 'root.html')


@app.route('/logout')
def logout():

    cookievars = get_cookie_vars(app.current_request.headers)
    template_vars = {'title': 'Logged Out', 'URS_URL': get_urs_url(app.current_request.context)}

    if cookievars:
        user_id = cookievars['urs-user-id']
        urs_access_token = cookievars['urs-access-token']
        delete_session(user_id, urs_access_token)
        template_vars['contentstring'] = 'You are logged out.'
    else:
        template_vars['contentstring'] = 'No active login found.'

    headers = {
        'Content-Type': 'text/html',
        'Set-Cookie': 'urs-access-token=deleted; Expires=; expires=Thu, 01 Jan 1970 00:00:00 GMT',
        'set-cookie': 'urs-user-id=deleted; Expires=; expires=Thu, 01 Jan 1970 00:00:00 GMT'
    }
    return make_html_response(template_vars, headers, 200, 'root.html')


@app.route('/login')
def login():

    args = app.current_request.query_params
    log.debug('the query_params: {}'.format(args))

    if not args:
        template_vars = {'contentstring': 'No params', 'title': 'Could Not Login'}
        headers = {}
        return make_html_response(template_vars, headers, 400, 'error.html')

    if 'code' not in args:
        contentstring = 'Did not get the required CODE from URS'
        if os.getenv('MATURITY', '') == 'DEV':
            contentstring += "<br /><h2>Params:</h2><ul>" + "\n".join(
                map(lambda x: '<li><b>{0}</b>: {1}</li>'.format(x, args[x]), args)) + "</ul>" if args else None

        template_vars = {'contentstring': contentstring, 'title': 'Could Not Login'}
        headers = {}
        return make_html_response(template_vars, headers, 400, 'error.html')
    else:
        log.debug('pre-do_auth() query params: {}'.format(app.current_request.query_params))
        redir_url = '{}{}'.format(get_endpoint(), 'login')
        auth = do_auth(app.current_request.query_params["code"], redir_url)
        log.debug('auth: {}'.format(auth))
        if not auth:
            log.debug('no auth returned from do_auth()')

            template_vars = {'contentstring': 'There was a problem talking to URS Login', 'title': 'Could Not Login'}

            return make_html_response(template_vars, {}, 400, 'error.html')

        user_id = auth['endpoint'].split('/')[-1]

        user_profile = get_profile(user_id, auth['access_token'])
        log.debug('Got the user profile: {}'.format(user_profile))
        if user_profile:
            log.debug('urs-access-token: {}'.format(auth['access_token']))
            if 'state' in args:
                redirect_to = args["state"]
            else:
                redirect_to = '/{}/'.format(STAGE)

            headers = {'Location': redirect_to}
            # Interesting worklaround: api gateway will technically only accept one of each type of header, but if you
            # specify your set-cookies with different alpha cases, you can actually send multiple.
            headers['Set-Cookie'] = 'urs-access-token={}; Expires={}'.format(auth['access_token'],
                                                                                           get_cookie_expiration_date_str())
            headers['set-cookie'] = 'urs-user-id={}; Expires={}'.format(user_id, get_cookie_expiration_date_str())

            return Response(body='', status_code=301, headers=headers)
        else:
            template_vars = {'contentstring': 'Could not get user profile from URS', 'title': 'Could Not Login'}
            return make_html_response(template_vars, {}, 400, 'error.html')


def get_range_header_val():

    if 'Range' in app.current_request.headers:
        return app.current_request.headers['Range']
    if 'range' in app.current_request.headers:
        return app.current_request.headers['range']
    return None


def get_data_dl_s3_client():

    cookievars = get_cookie_vars(app.current_request.headers)
    if cookievars:
        user_id = cookievars['urs-user-id']
    else:
        user_id = None
    session = get_role_session(user_id=user_id)
    params = {}
    BCCONFIG = {'user_agent': "Egress App for userid={0}".format(user_id)}
    if os.getenv('S3_SIGNATURE_VERSION'):
        BCCONFIG['signature_version'] = os.getenv('S3_SIGNATURE_VERSION')
    params['config'] = bc_Config(**BCCONFIG)
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
    #return 'Finish this thing'

    response_headers = {'Content-Type': download['ContentType']}
    for header in download['ResponseMetadata']['HTTPHeaders']:
        name = header_map[header] if header in header_map else header
        value = download['ResponseMetadata']['HTTPHeaders'][header] if header != 'server' else 'egress'
        log.debug("setting header {0} to {1}.".format(name, value))
        response_headers['name'] = value

    # response.headers.add('Content-Disposition', 'attachment; filename={0}'.format(filename))
    log.debug(response_headers)
    return Response(body='', headers=response_headers, status_code=200)


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
        user_profile = get_session(cookievars['urs-user-id'], cookievars['urs-access-token'])

    # Check for public bucket
    if check_public_bucket(bucket, public_buckets, b_map):
        log.debug("Accessing public bucket {0}".format(path))
    elif not user_profile:
        return do_auth_and_return(app.current_request.context)

    # Check that the bucket is either NOT private, or user belongs to that group
    private_check = check_private_bucket(bucket, private_buckets, b_map)
    log.debug('private check: {}'.format(private_check))
    u_in_g = user_in_group(private_check, cookievars, user_profile, False)
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
