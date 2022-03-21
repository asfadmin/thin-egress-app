import json
import os
import time
from functools import wraps
from typing import Optional
from urllib import request
from urllib.error import HTTPError
from urllib.parse import quote_plus, urlencode, urlparse

import cachetools
import flatdict
from botocore.config import Config as bc_Config
from botocore.exceptions import ClientError
from cachetools.func import ttl_cache
from cachetools.keys import hashkey
from chalice import Chalice, Response

try:
    from opentelemetry import trace
    from opentelemetry.propagate import inject
except ImportError:
    trace = None

    def inject(obj):
        return obj

from rain_api_core.aws_util import check_in_region_request, get_role_creds, get_role_session, get_yaml_file
from rain_api_core.bucket_map import BucketMap
from rain_api_core.egress_util import get_bucket_name_prefix, get_presigned_url
from rain_api_core.general_util import duration, get_log, log_context, return_timing_object
from rain_api_core.timer import Timer
from rain_api_core.urs_util import (
    do_login,
    get_new_token_and_profile,
    get_urs_creds,
    get_urs_url,
    user_in_group,
    user_profile_2_jwt_payload
)
from rain_api_core.view_util import (
    JWT_ALGO,
    JWT_COOKIE_NAME,
    get_cookie_vars,
    get_html_body,
    get_jwt_keys,
    make_set_cookie_headers_jwt
)


def with_trace(context=None):
    """Decorator for adding Open Telemetry tracing.

    context: An optional Open Telemetry context containing the span's parent.
      For top-level spans the context should be a truthy but invalid value e.g. {}.
      This will cause the newly created span to create its own context that will be
      passed to subsequent child spans.
    """
    def tracefunc(func):
        if trace is None:
            return func

        @wraps(func)
        def wrapper(*args, **kwargs):
            tracer = trace.get_tracer("tracer")

            with tracer.start_as_current_span(func.__name__, context):
                return func(*args, **kwargs)

        return wrapper
    return tracefunc


log = get_log()
conf_bucket = os.getenv('CONFIG_BUCKET', "rain-t-config")

# Here's a lifetime-of lambda cache of these values:
bucket_map_file = os.getenv('BUCKET_MAP_FILE', 'bucket_map.yaml')
b_map = None
# TODO(reweeden): Refactor when wrapped attributes are implemented
# https://github.com/tkem/cachetools/issues/176
get_bucket_region_cache = cachetools.LRUCache(maxsize=128)

STAGE = os.getenv('STAGE_NAME', 'DEV')


class TeaChalice(Chalice):
    def __call__(self, event, context):
        resource_path = event.get('requestContext', {}).get('resourcePath')
        origin_request_id = event.get('headers', {}).get('x-origin-request-id')
        log_context(route=resource_path, request_id=context.aws_request_id, origin_request_id=origin_request_id)
        # get_jwt_field() below generates log messages, so the above log_context() sets the
        # vars for it to use while it's doing the username lookup
        userid = get_jwt_field(get_cookie_vars(event.get('headers', {}) or {}), 'urs-user-id')
        log_context(user_id=userid)

        resp = super().__call__(event, context)

        resp['headers']['x-request-id'] = context.aws_request_id
        if origin_request_id:
            # If we were passed in an x-origin-request-id header, pass it out too
            resp['headers']['x-origin-request-id'] = origin_request_id

        log_context(user_id=None, route=None, request_id=None)

        return resp


app = TeaChalice(app_name='egress-lambda')


class TeaException(Exception):
    """ base exception for TEA """


class EulaException(TeaException):
    def __init__(self, payload: dict):
        self.payload = payload


@with_trace()
def get_request_id() -> str:
    assert app.lambda_context is not None

    return app.lambda_context.aws_request_id


@with_trace()
def get_origin_request_id() -> Optional[str]:
    assert app.current_request is not None

    return app.current_request.headers.get("x-origin-request-id")


@with_trace()
def get_aux_request_headers():
    req_headers = {"x-request-id": get_request_id()}
    origin_request_id = get_origin_request_id()

    if origin_request_id:
        req_headers["x-origin-request-id"] = origin_request_id

    # Insert Open Telemetry headers
    inject(req_headers)

    return req_headers


@with_trace()
def check_for_browser(hdrs):
    return 'user-agent' in hdrs and hdrs['user-agent'].lower().startswith('mozilla')


@with_trace()
def get_user_from_token(token):
    """
    This may be moved to rain-api-core.urs_util.py once things stabilize.
    Will query URS for user ID of requesting user based on token sent with request

    :param token: token received in request for data
    :return: user ID of requesting user.
    """

    urs_creds = get_urs_creds()

    params = {
        'client_id': urs_creds['UrsId'],
        # The client_id of the non SSO application you registered with Earthdata Login
        'token': token
    }

    base_url = os.getenv('AUTH_BASE_URL', 'https://urs.earthdata.nasa.gov')
    url = f'{base_url}/oauth/tokens/user?{urlencode(params)}'

    authval = f"Basic {urs_creds['UrsAuth']}"
    headers = {'Authorization': authval}

    # Tack on auxillary headers
    headers.update(get_aux_request_headers())
    log.debug(f'headers: {headers}, params: {params}')

    _time = time.time()

    req = request.Request(url, headers=headers, method='POST')
    try:
        response = request.urlopen(req)
    except HTTPError as e:
        response = e
        log.debug("%s", e)

    payload = response.read()
    log.info(return_timing_object(service="EDL", endpoint=url, method="POST", duration=duration(_time)))

    try:
        msg = json.loads(payload)
    except json.JSONDecodeError:
        log.error(f'could not get json message from payload: {payload}')
        msg = {}

    log.debug(f'raw payload: {payload}')
    log.debug(f'json loads: {msg}')
    log.debug(f'code: {response.code}')

    if response.code == 200:
        try:
            return msg['uid']
        except KeyError as e:
            log.error(
                f'Problem with return from URS: e: {e}, url: {url}, params: {params}, response payload: {payload}, ')
            return None
    elif response.code == 403:
        if 'error_description' in msg and 'eula' in msg['error_description'].lower():
            # sample json in this case:
            # `{"status_code": 403, "error_description": "EULA Acceptance Failure",
            #   "resolution_url": "http://uat.urs.earthdata.nasa.gov/approve_app?client_id=LqWhtVpLmwaD4VqHeoN7ww"}`
            log.warning('user needs to sign the EULA')
            raise EulaException(msg)
        # Probably an expired token if here
        log.warning(f'403 error from URS: {msg}')
    else:
        if 'error' in msg:
            errtxt = msg["error"]
        else:
            errtxt = ''
        if 'error_description' in msg:
            errtxt = errtxt + ' ' + msg['error_description']

        log.error(f'Error getting URS userid from token: {errtxt} with code {response.code}')
        log.debug(f'url: {url}, params: {params}, ')
    return None


@with_trace()
def cumulus_log_message(outcome: str, code: int, http_method: str, k_v: dict):
    k_v.update({'code': code, 'http_method': http_method, 'status': outcome, 'requestid': get_request_id()})
    print(json.dumps(k_v))


@with_trace()
def restore_bucket_vars():
    global b_map  # pylint: disable=global-statement

    log.debug('conf bucket: %s, bucket_map_file: %s', conf_bucket, bucket_map_file)
    if b_map is None:
        log.info('downloading various bucket configs from %s: bucketmapfile: %s, ', conf_bucket, bucket_map_file)

        b_map_dict = get_yaml_file(conf_bucket, bucket_map_file)
        reverse = os.getenv('USE_REVERSE_BUCKET_MAP', 'FALSE').lower() == 'true'

        log.debug('bucket map: %s', b_map_dict)
        b_map = BucketMap(
            b_map_dict,
            bucket_name_prefix=get_bucket_name_prefix(),
            reverse=reverse
        )
    else:
        log.info('reusing old bucket configs')


@with_trace()
def do_auth_and_return(ctxt):
    log.debug('context: %s', ctxt)
    here = ctxt['path']
    if os.getenv('DOMAIN_NAME'):
        # Pop STAGE value off the request if we have a custom domain
        # TODO(reweeden): python3.9 use `str.removeprefix`
        prefix = f'/{STAGE}'
        if here.startswith(prefix):
            here = here[len(prefix):]

    log.info("here will be %s", here)
    redirect_here = quote_plus(here)
    urs_url = get_urs_url(ctxt, redirect_here)
    log.info("Redirecting for auth: %s", urs_url)
    return Response(body='', status_code=302, headers={'Location': urs_url})


@with_trace()
def add_cors_headers(headers):
    assert app.current_request is not None

    # send CORS headers if we're configured to use them
    origin_header = app.current_request.headers.get('origin')
    if origin_header is not None:
        cors_origin = os.getenv("CORS_ORIGIN")
        if cors_origin and (origin_header.endswith(cors_origin) or origin_header.lower() == 'null'):
            headers['Access-Control-Allow-Origin'] = origin_header
            headers['Access-Control-Allow-Credentials'] = 'true'
        else:
            log.warning(f'Origin {origin_header} is not an approved CORS host: {cors_origin}')


@with_trace()
def make_redirect(to_url, headers=None, status_code=301):
    if headers is None:
        headers = {}
    headers['Location'] = to_url
    add_cors_headers(headers)
    log.info(f'Redirect created. to_url: {to_url}')
    cumulus_log_message('success', status_code, 'GET', {'redirect': 'yes', 'redirect_URL': to_url})
    log.debug(f'headers for redirect: {headers}')
    return Response(body='', headers=headers, status_code=status_code)


@with_trace()
def make_html_response(t_vars: dict, hdrs: dict, status_code: int = 200, template_file: str = 'root.html'):
    template_vars = {'STAGE': STAGE if not os.getenv('DOMAIN_NAME') else None, 'status_code': status_code}
    template_vars.update(t_vars)

    headers = {'Content-Type': 'text/html'}
    headers.update(hdrs)

    return Response(body=get_html_body(template_vars, template_file), status_code=status_code, headers=headers)


@with_trace()
def get_bcconfig(user_id: str) -> dict:
    bcconfig = {
        "user_agent": f"Thin Egress App for userid={user_id}",
        "s3": {"addressing_style": "path"},
        "connect_timeout": 600,
        "read_timeout": 600,
        "retries": {"max_attempts": 10}
    }

    signature_version = os.getenv('S3_SIGNATURE_VERSION')
    if signature_version:
        bcconfig['signature_version'] = signature_version

    return bcconfig


@with_trace()
@cachetools.cached(
    get_bucket_region_cache,
    # Cache by bucketname only
    key=lambda _, bucketname: hashkey(bucketname)
)
def get_bucket_region(session, bucketname) -> str:
    try:
        _time = time.time()
        bucket_region = session.client('s3').get_bucket_location(Bucket=bucketname)['LocationConstraint'] or 'us-east-1'
        log.info(return_timing_object(
            service="s3",
            endpoint=f"client().get_bucket_location({bucketname})",
            duration=duration(_time)
        ))
        log.debug("bucket %s is in region %s", bucketname, bucket_region)

        return bucket_region
    except ClientError as e:
        # We hit here if the download role cannot access a bucket, or if it doesn't exist
        log.error("Could not access download bucket %s: %s", bucketname, e)
        raise


@with_trace()
def get_user_ip():
    assert app.current_request is not None

    x_forwarded_for = app.current_request.headers.get('x-forwarded-for')
    if x_forwarded_for:
        ip = x_forwarded_for.replace(' ', '').split(',')[0]
        log.debug(f"x-fowarded-for: {x_forwarded_for}")
        log.info(f"Assuming {ip} is the users IP")
        return ip
    ip = app.current_request.context['identity']['sourceIp']
    log.debug(f"NO x_fowarded_for, using sourceIp: {ip} instead")
    return ip


@with_trace()
def try_download_from_bucket(bucket, filename, user_profile, headers: dict):
    timer = Timer()
    timer.mark()

    # Attempt to pull userid from profile
    user_id = None
    if isinstance(user_profile, dict):
        if 'urs-user-id' in user_profile:
            user_id = user_profile['urs-user-id']
        elif 'uid' in user_profile:
            user_id = user_profile['uid']
    log.info("User Id for download is %s", user_id)
    log_context(user_id=user_id)

    timer.mark("check_in_region_request()")
    is_in_region = check_in_region_request(get_user_ip())
    timer.mark("get_role_creds()")
    creds, offset = get_role_creds(user_id, is_in_region)
    timer.mark("get_role_session()")
    session = get_role_session(creds=creds, user_id=user_id)
    timer.mark("get_bucket_region()")

    try:
        bucket_region = get_bucket_region(session, bucket)
        timer.mark()
    except ClientError as e:
        try:
            code = e.response['ResponseMetadata']['HTTPStatusCode']
        except (AttributeError, KeyError, IndexError):
            code = 400
        log.debug(f'response: {e.response}')
        log.error(f'ClientError while {user_id} tried downloading {bucket}/{filename}: {e}')
        cumulus_log_message('failure', code, 'GET', {'reason': 'ClientError', 's3': f'{bucket}/{filename}'})
        template_vars = {'contentstring': 'There was a problem accessing download data.',
                         'title': 'Data Not Available',
                         'requestid': get_request_id(),
                         }

        headers = {}
        return make_html_response(template_vars, headers, code, 'error.html')

    log.debug('this region: %', os.getenv('AWS_DEFAULT_REGION', 'env var doesnt exist'))
    if bucket_region != os.getenv('AWS_DEFAULT_REGION'):
        log.warning(
            "bucket %s is in region %s, we are in region %s! "
            "This is double egress in Proxy mode!",
            bucket, bucket_region, os.getenv('AWS_DEFAULT_REGION')
        )
    client = get_bc_config_client(user_id)

    log.debug('timing for try_download_from_bucket(): ')
    timer.log_all(log)

    log.info("Attempting to download s3://%s/%s", bucket, filename)

    # We'll cache the size later.
    head_check = {}

    try:
        # Make sure this file exists, don't ACTUALLY download
        range_header = get_range_header_val()

        if not os.getenv("SUPPRESS_HEAD"):
            _time = time.time()
            head_check = client.head_object(Bucket=bucket, Key=filename, Range=(range_header or ""))
            log.info(return_timing_object(service="s3", endpoint="client.head_object()", duration=duration(_time)))

        redirheaders = {'Range': range_header} if range_header else {}

        expires_in = 3600 - offset
        redirheaders['Cache-Control'] = f'private, max-age={expires_in - 60}'
        if isinstance(headers, dict):
            log.debug('adding %s to redirheaders %s', headers, redirheaders)
            redirheaders.update(headers)

        # Generate URL
        presigned_url = get_presigned_url(creds, bucket, filename, bucket_region, expires_in, user_id)
        s3_host = urlparse(presigned_url).netloc
        log.debug("Presigned URL host was %s", s3_host)

        download_stat = {"bucket": bucket, "object": filename, "range": range_header}
        download_stat.update({"InRegion": "True" if is_in_region else "False"})
        size = head_check.get("ContentLength")
        if size is not None:
            download_stat.update({"size": size})

        log.info({"download": download_stat})

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
        template_vars = {'contentstring': 'Could not find requested data.',
                         'title': 'Data Not Available',
                         'requestid': get_request_id(), }
        headers = {}
        cumulus_log_message('failure', 404, 'GET',
                            {'reason': 'Could not find requested data', 's3': f'{bucket}/{filename}'})
        return make_html_response(template_vars, headers, 404, 'error.html')


@with_trace()
def get_jwt_field(cookievar: dict, fieldname: str):
    return cookievar.get(JWT_COOKIE_NAME, {}).get(fieldname, None)


@app.route('/')
@with_trace(context={})
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
@with_trace(context={})
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
@with_trace(context={})
def login():
    try:
        headers = {}
        aux_headers = get_aux_request_headers()
        status_code, template_vars, headers = do_login(
            app.current_request.query_params,
            app.current_request.context,
            os.getenv('COOKIE_DOMAIN', ''),
            aux_headers=aux_headers
        )
    except ClientError as e:
        log.error("%s", e)
        status_code = 500
        template_vars = {
            'contentstring': 'Client Error occurred. ',
            'title': 'Client Error',
        }
    if status_code == 301:
        return Response(body='', status_code=status_code, headers=headers)

    template_vars['requestid'] = get_request_id()
    return make_html_response(template_vars, headers, status_code, 'error.html')


@app.route('/version')
@with_trace(context={})
def version():
    log.info("Got a version request!")
    version_return = {'version_id': '<BUILD_ID>'}

    # If we've flushed, lets return the flush time.
    if os.getenv('BUMP'):
        version_return['last_flush'] = os.getenv('BUMP')

    return json.dumps(version_return)


@app.route('/locate')
@with_trace(context={})
def locate():
    query_params = app.current_request.query_params
    if query_params is None or query_params.get('bucket_name') is None:
        return Response(body='Required "bucket_name" query paramater not specified',
                        status_code=400,
                        headers={'Content-Type': 'text/plain'})
    bucket_name = query_params.get('bucket_name')
    bucket_map = collapse_bucket_configuration(get_yaml_file(conf_bucket, bucket_map_file)['MAP'])
    search_map = flatdict.FlatDict(bucket_map, delimiter='/')
    matching_paths = [key for key, value in search_map.items() if value == bucket_name]
    if (len(matching_paths) > 0):
        return Response(body=json.dumps(matching_paths),
                        status_code=200,
                        headers={'Content-Type': 'application/json'})
    return Response(body=f'No route defined for {bucket_name}',
                    status_code=404,
                    headers={'Content-Type': 'text/plain'})


@with_trace()
def collapse_bucket_configuration(bucket_map):
    for k, v in bucket_map.items():
        if isinstance(v, dict):
            if 'bucket' in v:
                bucket_map[k] = v['bucket']
            else:
                collapse_bucket_configuration(v)
    return bucket_map


@with_trace()
def get_range_header_val():
    if 'Range' in app.current_request.headers:
        return app.current_request.headers['Range']
    if 'range' in app.current_request.headers:
        return app.current_request.headers['range']
    return None


@with_trace()
def get_new_session_client(user_id):
    # Default Config
    params = {"config": bc_Config(**get_bcconfig(user_id))}
    session = get_role_session(user_id=user_id)

    _time = time.time()
    new_bc_client = session.client('s3', **params)
    log.info(return_timing_object(service="s3", endpoint="session.client()", duration=duration(_time)))
    return new_bc_client


# refresh bc_client after 50 minutes
@with_trace()
@ttl_cache(ttl=50 * 60)
def get_bc_config_client(user_id):
    return get_new_session_client(user_id)


@with_trace()
def get_data_dl_s3_client():
    user_id = get_jwt_field(get_cookie_vars(app.current_request.headers), 'urs-user-id')
    return get_bc_config_client(user_id)


@with_trace()
def try_download_head(bucket, filename):
    timer = Timer()

    timer.mark("get_data_dl_s3_client()")
    client = get_data_dl_s3_client()
    timer.mark("client.get_object()")
    # Check for range request
    range_header = get_range_header_val()
    try:
        _time = time.time()
        if not range_header:
            client.get_object(Bucket=bucket, Key=filename)
        else:
            # TODO: Should both `client.get_object()` be `client.head_object()` ?!?!?!
            log.info("Downloading range %s", range_header)
            client.get_object(Bucket=bucket, Key=filename, Range=range_header)
        log.info(return_timing_object(service="s3", endpoint="client.get_object()", duration=duration(_time)))
        timer.mark()
    except ClientError as e:
        log.warning("Could not get head for s3://%s/%s: %s", bucket, filename, e)
        # cumulus uses this log message for metrics purposes.

        template_vars = {'contentstring': 'File not found',
                         'title': 'File not found',
                         'requestid': get_request_id(), }
        headers = {}
        cumulus_log_message('failure', 404, 'HEAD',
                            {'reason': 'Could not find requested data', 's3': f'{bucket}/{filename}'})
        return make_html_response(template_vars, headers, 404, 'error.html')

    # Try Redirecting to HEAD. There should be a better way.
    user_id = get_jwt_field(get_cookie_vars(app.current_request.headers), 'urs-user-id')
    log_context(user_id=user_id)

    # Generate URL
    timer.mark("get_role_creds()")
    creds, offset = get_role_creds(user_id=user_id)
    url_lifespan = 3600 - offset

    session = get_role_session(creds=creds, user_id=user_id)
    timer.mark("get_bucket_region()")
    bucket_region = get_bucket_region(session, bucket)
    timer.mark("get_presigned_url()")
    presigned_url = get_presigned_url(creds, bucket, filename, bucket_region, url_lifespan, user_id, 'HEAD')
    timer.mark()

    s3_host = urlparse(presigned_url).netloc

    # Return a redirect to a HEAD
    log.debug("Presigned HEAD URL host was %s", s3_host)

    log.debug('timing for try_download_head()')
    timer.log_all(log)

    return make_redirect(presigned_url, {}, 303)


# Attempt to validate HEAD request
@app.route('/{proxy+}', methods=['HEAD'])
@with_trace(context={})
def dynamic_url_head():
    timer = Timer()
    timer.mark("restore_bucket_vars()")
    log.debug('attempting to HEAD a thing')
    restore_bucket_vars()
    timer.mark("b_map.get()")

    param = app.current_request.uri_params.get('proxy')
    if param is None:
        return Response(body='HEAD failed', headers={}, status_code=400)

    entry = b_map.get(param)
    timer.mark()

    log.debug("entry: %s", entry)

    if entry is None:
        template_vars = {
            'contentstring': 'Bucket not available',
            'title': 'Bucket not available',
            'requestid': get_request_id()
        }
        headers = {}
        return make_html_response(template_vars, headers, 404, 'error.html')
    timer.mark()
    log.debug('timing for dynamic_url_head()')
    timer.log_all(log)

    return try_download_head(entry.bucket, entry.object_key)


@with_trace()
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
        # TODO(reweeden): changing the response based on user agent looks like a really bad idea...
        if check_for_browser(app.current_request.headers):
            template_vars = {
                'title': e.payload['error_description'],
                'status_code': 403,
                'contentstring': (
                    f'Could not fetch data because "{e.payload["error_description"]}". Please accept EULA here: '
                    f'<a href="{e.payload["resolution_url"]}">{e.payload["resolution_url"]}</a> and try again.'
                ),
                'requestid': get_request_id(),
            }

            return 'return', make_html_response(template_vars, {}, 403, 'error.html')
        return 'return', Response(body=e.payload, status_code=403, headers={})

    if user_id:
        log_context(user_id=user_id)
        aux_headers = get_aux_request_headers()
        user_profile = get_new_token_and_profile(user_id, True, aux_headers=aux_headers)
        if user_profile:
            return 'user_profile', user_profile

    return 'return', do_auth_and_return(app.current_request.context)


@app.route('/{proxy+}', methods=['GET'])
@with_trace(context={})
def dynamic_url():
    timer = Timer()
    timer.mark("restore_bucket_vars()")

    log.debug('attempting to GET a thing')
    restore_bucket_vars()
    log.debug(f'b_map: {b_map.bucket_map}')
    timer.mark()

    log.info(app.current_request.headers)

    param = app.current_request.uri_params.get("proxy")
    entry = None
    if param is not None:
        entry = b_map.get(param)

    log.debug('entry: %s', entry)

    if not entry:
        template_vars = {
            'contentstring': 'File not found',
            'title': 'File not found',
            'requestid': get_request_id(),
        }
        headers = {}
        return make_html_response(template_vars, headers, 404, 'error.html')

    if not entry.object_key:
        log.warning('Request was made to directory listing instead of object: %s', entry.bucket_path)

        template_vars = {
            'contentstring': 'Request does not appear to be valid.',
            'title': 'Request Not Serviceable',
            'requestid': get_request_id()
        }
        headers = {}
        return make_html_response(template_vars, headers, 404, 'error.html')

    custom_headers = dict(entry.headers)
    cookievars = get_cookie_vars(app.current_request.headers)
    user_profile = None
    if cookievars:
        log.debug('cookievars: %s', cookievars)
        if JWT_COOKIE_NAME in cookievars:
            # this means our cookie is a jwt and we don't need to go digging in the session db
            user_profile = cookievars[JWT_COOKIE_NAME]
        else:
            log.warning('jwt cookie not found')
            # Not kicking user out just yet. We might be dealing with a public bucket
    timer.mark("get_required_groups()")
    # It's only necessary to be in one of these groups
    required_groups = entry.get_required_groups()
    log.debug('required_groups: %s', required_groups)
    # Check for public bucket
    timer.mark("possible auth header handling")
    if required_groups is None:
        log.debug("Accessing public bucket %s => %s", entry.bucket_path, entry.bucket)
    elif not user_profile:
        authorization = app.current_request.headers.get('Authorization')
        if not authorization:
            return do_auth_and_return(app.current_request.context)

        method, token, *_ = authorization.split()
        method = method.lower()

        if method == "bearer":
            # we will deal with "bearer" auth here. "Basic" auth will be handled by do_auth_and_return()
            log.debug('we got an Authorization header. %s', authorization)
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
            cookievars[JWT_COOKIE_NAME] = jwt_payload
        else:
            return do_auth_and_return(app.current_request.context)

    timer.mark("user_in_group()")
    aux_headers = get_aux_request_headers()
    u_in_g, new_user_profile = user_in_group(required_groups, cookievars, False, aux_headers=aux_headers)
    timer.mark()

    new_jwt_cookie_headers = {}
    if new_user_profile:
        log.debug(f"We got new profile from user_in_group() {new_user_profile}")
        user_profile = new_user_profile
        jwt_cookie_payload = user_profile_2_jwt_payload(get_jwt_field(cookievars, 'urs-user-id'),
                                                        get_jwt_field(cookievars, 'urs-access-token'),
                                                        user_profile)
        new_jwt_cookie_headers.update(
            make_set_cookie_headers_jwt(jwt_cookie_payload, '', os.getenv('COOKIE_DOMAIN', '')))

    log.debug('user_in_group: %s', u_in_g)

    # Check that the bucket is either NOT private, or user belongs to that group
    if required_groups and not u_in_g:
        template_vars = {
            'contentstring': 'This data is not currently available.',
            'title': 'Could not access data',
            'requestid': get_request_id()
        }
        return make_html_response(template_vars, new_jwt_cookie_headers, 403, 'error.html')

    custom_headers.update(new_jwt_cookie_headers)
    log.debug(f'custom headers before try download from bucket: {custom_headers}')
    timer.mark()

    log.debug("timing for dynamic_url()")
    timer.log_all(log)

    return try_download_from_bucket(entry.bucket, entry.object_key, user_profile, custom_headers)


@app.route('/profile')
@with_trace(context={})
def profile():
    return Response(body='Profile not available.',
                    status_code=200, headers={})


@app.route('/pubkey', methods=['GET'])
@with_trace(context={})
def pubkey():
    thebody = json.dumps({
        'rsa_pub_key': str(get_jwt_keys()['rsa_pub_key'].decode()),
        'algorithm': JWT_ALGO
    })
    return Response(body=thebody,
                    status_code=200,
                    headers={'content-type': 'application/json'})
