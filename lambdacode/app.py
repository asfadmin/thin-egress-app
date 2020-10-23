from chalice import Chalice, Response
from botocore.config import Config as bc_Config
from botocore.exceptions import ClientError
import flatdict
import os
import json

import time

from urllib import request
from urllib.error import HTTPError
from urllib.parse import urlparse, quote_plus, urlencode

from rain_api_core.general_util import get_log, log_context
from rain_api_core.urs_util import get_urs_url, do_login, user_in_group, get_urs_creds, user_profile_2_jwt_payload, get_new_token_and_profile
from rain_api_core.aws_util import get_yaml_file, get_s3_resource, get_role_session, get_role_creds, check_in_region_request
from rain_api_core.view_util import get_html_body, get_cookie_vars, make_set_cookie_headers_jwt, JWT_COOKIE_NAME
from rain_api_core.egress_util import get_presigned_url, process_request, check_private_bucket, check_public_bucket


log = get_log()
conf_bucket = os.getenv('CONFIG_BUCKET', "rain-t-config")

# Here's a lifetime-of lambda cache of these values:
bucket_map_file = os.getenv('BUCKET_MAP_FILE', 'bucket_map.yaml')
b_map = None
b_region_map = {}
bc_client_cache = {}
s3_resource = get_s3_resource()

STAGE = os.getenv('STAGE_NAME', 'DEV')
header_map = {'date':           'Date',
              'last-modified':  'Last-Modified',
              'accept-ranges':  'Accept-Ranges',
              'etag':           'ETag',
              'content-type':   'Content-Type',
              'content-length': 'Content-Length'}


class TeaChalice(Chalice):
    def __call__(self, event, context):
        resource_path = event.get('requestContext', {}).get('resourcePath')
        log_context(route=resource_path, request_id=context.aws_request_id)
        # get_jwt_field() below generates log messages, so the above log_context() sets the
        # vars for it to use while it's doing the username lookup
        userid = get_jwt_field(get_cookie_vars(event['headers']), 'urs-user-id')
        log_context(user_id=userid)

        resp = super().__call__(event, context)

        resp['headers'].update({'x-request-id': context.aws_request_id})
        log_context(user_id=None, route=None, request_id=None)

        return resp


app = TeaChalice(app_name='egress-lambda')

class TeaException(Exception):
    """ base exception for TEA """


class EulaException(TeaException):
    def __init__(self, payload:dict):
        self.payload = payload


def check_for_browser(hdrs):
    return 'user-agent' in hdrs and hdrs['user-agent'].lower().startswith('mozilla')


def get_user_from_token(token):
    """
    This may be moved to rain-api-core.urs_util.py once things stabilize.
    Will query URS for user ID of requesting user based on token sent with request

    :param token: token received in request for data
    :return: user ID of requesting user.
    """

    params = {
        'client_id': get_urs_creds()['UrsId'],
        # The client_id of the non SSO application you registered with Earthdata Login
        'token': token
    }

    url = '{}/oauth/tokens/user?{}'.format(os.getenv('AUTH_BASE_URL', 'https://urs.earthdata.nasa.gov'),
                                           urlencode(params))

    authval = "Basic {}".format(get_urs_creds()['UrsAuth'])
    headers = {'Authorization': authval}

    log.debug(f'headers: {headers}, params: {params}')

    req = request.Request(url, headers=headers, method='POST')
    try:
        response = request.urlopen(req)
    except HTTPError as e:
        response = e
        log.debug(e)

    payload = response.read()

    try:
        msg = json.loads(payload)
    except json.JSONDecodeError as e:
        log.error(f'could not get json message from payload: {payload}')
        msg = {}

    log.debug(f'raw payload: {payload}')
    log.debug(f'json loads: {msg}')
    log.debug(f'code: {response.code}')

    if response.code == 200:
        try:
            return msg['uid']
        except KeyError as e:
            log.error(f'Problem with return from URS: e: {e}, url: {url}, params: {params}, response payload: {payload}, ')
            return None
    elif response.code == 403:
        if 'error_description' in msg and 'eula' in msg['error_description'].lower():
            # sample json in this case: `{"status_code":403,"error_description":"EULA Acceptance Failure","resolution_url":"http://uat.urs.earthdata.nasa.gov/approve_app?client_id=LqWhtVpLmwaD4VqHeoN7ww"}`
            log.warning('user needs to sign the EULA')
            raise EulaException(msg)
        # Probably an expired token if here
        log.warning(f'403 error from URS: {msg}')
    else:
        if 'error' in msg:
            errtxt = msg["error"]
        else:
            errtxt = f''
        if 'error_description' in msg:
            errtxt = errtxt + ' ' + msg['error_description']

        log.error(f'Error getting URS userid from token: {errtxt} with code {response.code}')
        log.debug(f'url: {url}, params: {params}, ')
    return None


def cumulus_log_message(outcome: str, code: int, http_method:str, k_v: dict):
    k_v.update({'code': code, 'http_method': http_method, 'status': outcome})
    jsonstr = json.dumps(k_v)
    print(f'{jsonstr}')


def restore_bucket_vars():

    global b_map                                                                       #pylint: disable=global-statement

    log.debug('conf bucket: {}, bucket_map_file: {}'.format(conf_bucket,bucket_map_file))
    if b_map is None:
        log.info('downloading various bucket configs from {}: bucketmapfile: {}, '.format(conf_bucket,bucket_map_file))

        b_map = get_yaml_file(conf_bucket, bucket_map_file, s3_resource)
        log.debug('bucket map: {}'.format(b_map))
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


def make_redirect(to_url, headers=None, status_code=301):
    if headers is None:
        headers = {}
    headers['Location'] = to_url
    log.info(f'Redirect created. to_url: {to_url}')
    cumulus_log_message('success', status_code, 'GET', {'redirect': 'yes', 'redirect_URL': to_url})
    log.debug(f'headers for redirect: {headers}')
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
    if bucketname in b_region_map:
        return b_region_map[bucketname]

    try:
        bucket_region = session.client('s3', **params).get_bucket_location(Bucket=bucketname)['LocationConstraint']
        bucket_region = 'us-east-1' if not bucket_region else bucket_region

        log.debug("bucket {0} is in region {1}".format(bucketname, bucket_region))
    except ClientError as e:
        # We hit here if the download role cannot access a bucket, or if it doesn't exist
        log.error("Could not access download bucket {0}: {1}".format(bucketname, e))
        raise

    b_region_map[bucketname] = bucket_region

    return bucket_region


def try_download_from_bucket(bucket, filename, user_profile, headers: dict):


    # Attempt to pull userid from profile
    user_id = None
    if isinstance(user_profile, dict):
        if 'urs-user-id' in user_profile :
            user_id = user_profile['urs-user-id']
        elif 'uid' in user_profile:
            user_id = user_profile['uid']
    log.info("User Id for download is {0}".format(user_id))
    log_context(user_id=user_id)

    t0 = time.time()
    is_in_region = check_in_region_request(app.current_request.context['identity']['sourceIp'])
    t1 = time.time()
    creds, offset = get_role_creds(user_id, is_in_region)
    t2 = time.time()
    session = get_role_session(creds=creds, user_id=user_id)
    t3 = time.time()

    try:
        bucket_region = get_bucket_region(session, bucket)
        t4 = time.time()
    except ClientError as e:
        try:
            code = e.response['ResponseMetadata']['HTTPStatusCode']
        except (AttributeError, KeyError, IndexError):
            code = 400
        log.debug(f'response: {e.response}')
        log.error(f'ClientError while {user_id} tried downloading {bucket}/{filename}: {e}')
        cumulus_log_message('failure', code, 'GET', {'reason': 'ClientError', 's3': f'{bucket}/{filename}'})
        template_vars = {'contentstring': 'There was a problem accessing download data.', 'title': 'Data Not Available'}
        headers = {}
        return make_html_response(template_vars, headers, code, 'error.html')

    log.debug('this region: {}'.format(os.getenv('AWS_DEFAULT_REGION', 'env var doesnt exist')))
    if bucket_region != os.getenv('AWS_DEFAULT_REGION'):
        log.warning("bucket {0} is in region {1}, we are in region {2}! " +
                    "This is double egress in Proxy mode!".format(bucket,
                                                                  bucket_region,
                                                                  os.getenv('AWS_DEFAULT_REGION')))
    client = get_bc_config_client(user_id)

    log.debug('timing for try_download_from_bucket(): ')
    log.debug('ET for check_in_region_request(): {}s'.format(t1 - t0))
    log.debug('ET for get_role_creds(): {}s'.format(t2 - t1))
    log.debug('ET for get_role_session(): {}s'.format(t3 - t2))
    log.debug('ET for get_bucket_region(): {}s'.format(t4 - t3))
    log.debug('ET for total: {}'.format(t4 - t0))


    log.info("Attempting to download s3://{0}/{1}".format(bucket, filename))

    try:
        # Make sure this file exists, don't ACTUALLY download
        range_header = get_range_header_val()
        if not range_header:
            if not os.getenv("SUPPRESS_HEAD"):
                client.head_object(Bucket=bucket, Key=filename)
            redirheaders = {}
        else:
            if not os.getenv("SUPPRESS_HEAD"):
                client.head_object(Bucket=bucket, Key=filename, Range=range_header)
            redirheaders = {'Range': range_header}

        expires_in = 3600 - offset
        redirheaders['Cache-Control'] = 'private, max-age={0}'.format(expires_in - 60)
        if isinstance(headers, dict):
            log.debug(f'adding {headers} to redirheaders {redirheaders}')
            redirheaders.update(headers)

        # Generate URL
        presigned_url = get_presigned_url(creds, bucket, filename, bucket_region, expires_in, user_id)
        s3_host = urlparse(presigned_url).netloc
        log.debug("Presigned URL host was {0}".format(s3_host))

        return make_redirect(presigned_url, redirheaders, 303)

    except ClientError as e:
        # Watch for bad range request:
        if e.response['ResponseMetadata']['HTTPStatusCode'] == 416:
            # cumulus uses this log message for metrics purposes.
            log.error(f"Invalid Range 416, Could not get range {get_range_header_val()} s3://{bucket}/{filename}: {e}")
            cumulus_log_message('failure', 416, 'GET', {'reason': 'Invalid Range',
                                                        's3': f'{bucket}/{filename}',
                                                        'range': get_range_header_val()})
            return Response(body='Invalid Range', status_code=416, headers={})


        # cumulus uses this log message for metrics purposes.
        log.warning("Could not download s3://{0}/{1}: {2}".format(bucket, filename, e))
        template_vars = {'contentstring': 'Could not find requested data.', 'title': 'Data Not Available'}
        headers = {}
        cumulus_log_message('failure', 404, 'GET', {'reason': 'Could not find requested data', 's3': f'{bucket}/{filename}'})
        return make_html_response(template_vars, headers, 404, 'error.html')


def get_jwt_field(cookievar: dict, fieldname: str):
    return cookievar.get(JWT_COOKIE_NAME, {}).get(fieldname, None)


@app.route('/')
def root():
    user_profile = False
    template_vars = {'title': 'Welcome'}

    cookievars = get_cookie_vars(app.current_request.headers)
    if cookievars:
        if JWT_COOKIE_NAME in cookievars:
            # We have a JWT cookie
            user_profile = cookievars[JWT_COOKIE_NAME]

    if user_profile:
        if 'urs-user-id' in user_profile:
            log_context(user_id=user_profile['urs-user-id'])
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

    if JWT_COOKIE_NAME in cookievars:

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
    log.info("Got a version request!")
    return json.dumps({'version_id': '<BUILD_ID>'})


@app.route('/locate')
def locate():
    query_params = app.current_request.query_params
    if query_params is None or query_params.get('bucket_name') is None:
        return Response(body='Required "bucket_name" query paramater not specified',
                        status_code=400,
                        headers={'Content-Type': 'text/plain'})
    bucket_name = app.current_request.query_params.get('bucket_name', None)
    bucket_map = collapse_bucket_configuration(get_yaml_file(conf_bucket,
                                                             bucket_map_file,
                                                             s3_resource)['MAP'])
    search_map = flatdict.FlatDict(bucket_map, delimiter='/')
    matching_paths = [key for key, value in search_map.items() if value == bucket_name]
    if(len(matching_paths) > 0):
        return Response(body=json.dumps(matching_paths),
                        status_code=200,
                        headers={'Content-Type': 'application/json'})
    return Response(body=f'No route defined for {bucket_name}',
                    status_code=404,
                    headers={'Content-Type': 'text/plain'})


def collapse_bucket_configuration(bucket_map):
    for k, v in bucket_map.items():
        if isinstance(v, dict):
            if 'bucket' in v:
                bucket_map[k] = v['bucket']
            else:
                collapse_bucket_configuration(v)
    return bucket_map


def get_range_header_val():

    if 'Range' in app.current_request.headers:
        return app.current_request.headers['Range']
    if 'range' in app.current_request.headers:
        return app.current_request.headers['range']
    return None


def get_bc_config_client(user_id):
    params = {}
    now = time.time()

    if user_id not in bc_client_cache:
        # This a new user, generate a new bc_Config client
        params['config'] = bc_Config(**get_bcconfig(user_id))
        session = get_role_session(user_id=user_id)
        bc_client_cache[user_id] = {"client": session.client('s3', **params), "timestamp": now }
    elif now - bc_client_cache[user_id]["timestamp"] >= (50*60):
        # Replace the client if is more than 50 minutes old
        log.info(f"Replacing old bc_Config_client for user {user_id}")
        params['config'] = bc_Config(**get_bcconfig(user_id))
        session = get_role_session(user_id=user_id)
        bc_client_cache[user_id] = {"client": session.client('s3', **params), "timestamp": now }

    return bc_client_cache[user_id]["client"]


def get_data_dl_s3_client():
    user_id = get_jwt_field(get_cookie_vars(app.current_request.headers), 'urs-user-id')
    return get_bc_config_client(user_id)


def try_download_head(bucket, filename):
    t = [time.time()]
    client = get_data_dl_s3_client()
    t.append(time.time())
    # Check for range request
    range_header = get_range_header_val()
    try:
        if not range_header:
            download = client.get_object(Bucket=bucket, Key=filename)
        else:
            log.info("Downloading range {0}".format(range_header))
            download = client.get_object(Bucket=bucket, Key=filename, Range=range_header)
        t.append(time.time())
    except ClientError as e:
        log.warning("Could not get head for s3://{0}/{1}: {2}".format(bucket, filename, e))
        # cumulus uses this log message for metrics purposes.

        template_vars = {'contentstring': 'File not found',
                         'title': 'File not found'}
        headers = {}
        cumulus_log_message('failure', 404, 'HEAD', {'reason': 'Could not find requested data', 's3': f'{bucket}/{filename}'})
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
    log_context(user_id=user_id)

    # Generate URL
    t.append(time.time())
    creds, offset = get_role_creds(user_id=user_id)
    url_lifespan = 3600 - offset
    bucket_region = client.get_bucket_location(Bucket=bucket)['LocationConstraint']
    bucket_region = 'us-east-1' if not bucket_region else bucket_region
    t.append(time.time())
    presigned_url = get_presigned_url(creds, bucket, filename, bucket_region, url_lifespan, user_id, 'HEAD')
    t.append(time.time())
    s3_host = urlparse(presigned_url).netloc

    # Return a redirect to a HEAD
    log.debug("Presigned HEAD URL host was {0}".format(s3_host))
    log.debug('timing for try_download_head()')
    log.debug('ET for get_data_dl_s3_client(): {}s'.format(t[1] - t[0]))
    log.debug('ET for client.get_object(): {}s'.format(t[2] - t[1]))
    log.debug('ET for get_role_creds(): {}s'.format(t[4] - t[3]))
    log.debug('ET for get_presigned_url(): {}s'.format(t[5] - t[4]))


    return make_redirect(presigned_url, {}, 303)


# Attempt to validate HEAD request
@app.route('/{proxy+}', methods=['HEAD'])
def dynamic_url_head():
    t = [time.time()]
    log.debug('attempting to HEAD a thing')
    restore_bucket_vars()
    t.append(time.time())

    if 'proxy' in app.current_request.uri_params:
        path, bucket, filename, custom_headers = process_request(app.current_request.uri_params['proxy'], b_map)
        t.append(time.time())

        process_results = 'path: {}, bucket: {}, filename:{}'.format(path, bucket, filename)
        log.debug(process_results)

        if not bucket:
            template_vars = {'contentstring': 'Bucket not available',
                             'title': 'Bucket not available'}
            headers = {}
            return make_html_response(template_vars, headers, 404, 'error.html')
        t.append(time.time())
        log.debug('timing for dynamic_url_head()')
        log.debug('ET for restore_bucket_vars(): {}s'.format(t[1] - t[0]))
        log.debug('ET for process_request(): {}s'.format(t[2] - t[1]))
        log.debug('ET for total: {}s'.format(t[3] - t[0]))

        return try_download_head(bucket, filename)
    return Response(body='HEAD failed', headers={}, status_code=400)


def handle_auth_bearer_header(token):
    """
    Will handle the output from get_user_from_token in context of a chalice function. If user_id is determined,
    returns it. If user_id is not determined returns data to be returned

    :param token:
    :return: action, data
    """
    try:
        user_id = get_user_from_token(token)
    except EulaException as e:

        log.warning('user has not accepted EULA')
        if check_for_browser(app.current_request.headers):
            template_vars = {'title': e.payload['error_description'],
                             'status_code': 403,
                             'contentstring': f'Could not fetch data because "{e.payload["error_description"]}". Please accept EULA here: <a href="{e.payload["resolution_url"]}">{e.payload["resolution_url"]}</a> and try again.'
                             }

            return 'return', make_html_response(template_vars, {}, 403, 'error.html')
        return 'return', Response(body=e.payload, status_code=403, headers={})

    if user_id:
        log_context(user_id=user_id)
        user_profile = get_new_token_and_profile(user_id, True)
        if user_profile:
            return 'user_profile', user_profile

    return 'return', do_auth_and_return(app.current_request.context)


@app.route('/{proxy+}', methods=['GET'])
def dynamic_url():
    t = [time.time()]
    custom_headers = {}
    log.debug('attempting to GET a thing')
    restore_bucket_vars()
    log.debug(f'b_map: {b_map}')
    t.append(time.time())

    if 'proxy' in app.current_request.uri_params:
        path, bucket, filename, custom_headers = process_request(app.current_request.uri_params['proxy'], b_map)
        log.debug('path, bucket, filename, custom_headers: {}'.format(( path, bucket, filename, custom_headers)))
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
        if JWT_COOKIE_NAME in cookievars:
            # this means our cookie is a jwt and we don't need to go digging in the session db
            user_profile = cookievars[JWT_COOKIE_NAME]
        else:
            log.warning('jwt cookie not found')
            # Not kicking user out just yet. We might be dealing with a public bucket
    t.append(time.time())  # 2
    # Check for public bucket
    pub_bucket = check_public_bucket(bucket, b_map)
    t.append(time.time())  # 3
    if pub_bucket:
        log.debug("Accessing public bucket {0}".format(path))
    elif not user_profile:
        if 'Authorization' in app.current_request.headers and app.current_request.headers['Authorization'].split()[0].lower() == 'bearer':
            # we will deal with "bearer" auth here. "Basic" auth will be handled by do_auth_and_return()
            log.debug('we got an Authorization header. {}'.format(app.current_request.headers['Authorization']))
            token = app.current_request.headers['Authorization'].split()[1]
            action, data = handle_auth_bearer_header(token)

            if action == 'return':
                # Not a successful event.
                return data

            user_profile = data
            user_id = user_profile['uid']
            log_context(user_id=user_id)
            log.debug(f'User {user_id} has user profile: {user_profile}')
            jwt_payload = user_profile_2_jwt_payload(user_id, token, user_profile)
            log.debug(f"Encoding JWT_PAYLOAD: {jwt_payload}")
            custom_headers.update(make_set_cookie_headers_jwt(jwt_payload, '', os.getenv('COOKIE_DOMAIN', '')))

        else:
            return do_auth_and_return(app.current_request.context)

    t.append(time.time())  # 4
    # Check that the bucket is either NOT private, or user belongs to that group
    private_check = check_private_bucket(bucket, b_map)  # NOTE: Is an optimization attempt worth it
                                                         # if we're asking for a public file and we
                                                         # omit this check?
                                                         # omit this check?
    log.debug('private check: {}'.format(private_check))
    t.append(time.time())  # 5
    u_in_g, new_user_profile = user_in_group(private_check, cookievars, user_profile, False)
    t.append(time.time())  # 6

    new_jwt_cookie_headers = {}
    if new_user_profile:
        log.debug(f"We got new profile from user_in_group() {new_user_profile}")
        user_profile = new_user_profile
        jwt_cookie_payload = user_profile_2_jwt_payload(get_jwt_field(cookievars, 'urs-user-id'),
                                                        get_jwt_field(cookievars, 'urs-access-token'),
                                                        user_profile)
        new_jwt_cookie_headers.update(make_set_cookie_headers_jwt(jwt_cookie_payload, '', os.getenv('COOKIE_DOMAIN', '')))

    log.debug('user_in_group: {}'.format(u_in_g))

    if private_check and not u_in_g:
        template_vars = {'contentstring': 'This data is not currently available.', 'title': 'Could not access data'}
        return make_html_response(template_vars, new_jwt_cookie_headers, 403, 'error.html')

    if not filename:  # Maybe this belongs up above, right after setting the filename var?
        log.warning("Request was made to directory listing instead of object: {0}".format(path))

        template_vars = {'contentstring': 'Request does not appear to be valid.', 'title': 'Request Not Serviceable'}

        return make_html_response(template_vars, new_jwt_cookie_headers, 404, 'error.html')

    custom_headers.update(new_jwt_cookie_headers)
    log.debug(f'custom headers before try download from bucket: {custom_headers}')
    t.append(time.time())  # 7

    log.debug('timing for dynamic_url()')
    log.debug('ET for restore_bucket_vars(): {}s'.format(t[1] - t[0]))
    log.debug('ET for check_public_bucket(): {}s'.format(t[3] - t[2]))
    log.debug('ET for possible auth header handling: {}s'.format(t[4] - t[3]))
    log.debug('ET for user_in_group(): {}s'.format(t[6] - t[5]))
    log.debug('ET for total: {}s'.format(t[7] - t[0]))

    return try_download_from_bucket(bucket, filename, user_profile, custom_headers)


@app.route('/profile')
def profile():
    return Response(body='Profile not available.',
                    status_code=200, headers={})
