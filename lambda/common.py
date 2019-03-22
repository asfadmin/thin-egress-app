import boto3
from botocore.config import Config as bc_Config
from botocore.exceptions import ClientError
#import base64 # potentially used by get_urs_creds()
from jinja2 import Environment, FileSystemLoader, select_autoescape
import json
import logging
import os
import sys
import urllib
import time
import hmac
import hashlib
import re
import yaml
from datetime import datetime

from wsgiref.handlers import format_date_time as format_7231_date

header_map = {'date': 	        'Date',
              'last-modified':  'Last-Modified',
              'accept-ranges':  'Accept-Ranges',
              'etag': 	        'ETag',
              'content-type':   'Content-Type',
              'content-length': 'Content-Length'}

log = logging.getLogger(__name__)

STAGE = os.getenv('STAGE_NAME', 'DEV')

active_sessions = {}
session_store = os.getenv('SESSION_STORE', 'DB')
sessttl = int(os.getenv('SESSION_TTL', '168')) * 60 * 60
if session_store == 'DB':
    ddb = boto3.client('dynamodb')
    sesstable = os.getenv('SESSION_TABLE')
else:
    ddb = sesstable = None


def get_yaml_file(bucket, key):

    if not key:
        # No file was provided, send empty dict
        return {}
    try:
        log.info("Attempting to download yaml s3://{0}/{1}".format(bucket, key))
        optional_file = get_yaml( bucket, key )
        return optional_file
    except ClientError as e:
        # The specified file did not exist
        log.error("Could not download yaml @ s3://{0}/{1}: {2}".format(bucket, key, e))
        sys.exit()


def get_log():
    loglevel = os.getenv('LOGLEVEL', 'INFO')
    log_fmt_str = "%(levelname)s: %(message)s (%(filename)s line %(lineno)d/" + \
                  os.getenv("BUILD_VERSION", "NOBUILD") + "/" + \
                  os.getenv('MATURITY', 'DEV') + ")"

    logger = logging.getLogger()
    for h in logger.handlers:
        logger.removeHandler(h)

    h = logging.StreamHandler(sys.stdout)

    # use whatever format you want here
    FORMAT = '%(asctime)s %(message)s'
    h.setFormatter(logging.Formatter(log_fmt_str))
    logger.addHandler(h)
    logger.setLevel(getattr(logging, loglevel))

    if os.getenv("QUIETBOTO", 'TRUE').upper() == 'TRUE':
        # BOTO, be quiet plz
        logging.getLogger('boto3').setLevel(logging.CRITICAL)
        logging.getLogger('botocore').setLevel(logging.CRITICAL)
        logging.getLogger('nose').setLevel(logging.CRITICAL)
        logging.getLogger('elasticsearch').setLevel(logging.CRITICAL)
        logging.getLogger('s3transfer').setLevel(logging.CRITICAL)
        logging.getLogger('urllib3').setLevel(logging.CRITICAL)
        logging.getLogger('connectionpool').setLevel(logging.CRITICAL)
    else:
        logging.getLogger('boto3').setLevel(logging.INFO)
        logging.getLogger('botocore').setLevel(logging.INFO)
        logging.getLogger('nose').setLevel(logging.INFO)
        logging.getLogger('elasticsearch').setLevel(logging.INFO)
        logging.getLogger('s3transfer').setLevel(logging.INFO)
        logging.getLogger('urllib3').setLevel(logging.INFO)
        logging.getLogger('connectionpool').setLevel(logging.INFO)

    return logger


def get_urs_url(ctxt, to=False):

    base_url = os.getenv('AUTH_BASE_URL', 'https://urs.earthdata.nasa.gov') + '/oauth/authorize'

    # From URS Application
    client_id = get_urs_creds()['client_id']
    redirect_url = 'https://{}/{}/login'.format(ctxt['domainName'], ctxt['stage'])
    urs_url = '{0}?client_id={1}&response_type=code&redirect_uri={2}'.format(base_url, client_id, redirect_url)
    if to:
        urs_url += "&state={0}".format(to)

    # Try to handle scripts
    agent_pattern = re.compile('^(curl|wget|aria2|python)', re.IGNORECASE)

    try:
        download_agent = ctxt['identity']['userAgent']
    except IndexError:
        log.debug("No User Agent!")
        return urs_url

    if agent_pattern.match(download_agent):
        urs_url += "&app_type=401"

    return urs_url


def get_yaml(bucket, file_name):

    try:
        cfg_yaml = read_s3(bucket, file_name)
        return yaml.safe_load(cfg_yaml)
    except ClientError as e:
        log.error('Had trouble getting yaml file s3://{}/{}, {}'.format(bucket, file_name, e))
        raise


def get_s3_resource():

    params = {}
    # Swift signature compatability
    if os.getenv('S3_SIGNATURE_VERSION'):
        params['config'] = bc_Config(signature_version=os.getenv('S3_SIGNATURE_VERSION'))
    s3 = boto3.resource('s3', **params)
    return s3


def write_s3(bucket, key, data):

    log.debug("Writing data to s3://{1}/{0}".format(key, bucket))
    params = {}
    # Swift signature compatability
    if os.getenv('S3_SIGNATURE_VERSION'):
        params['config'] = bc_Config(signature_version=os.getenv('S3_SIGNATURE_VERSION'))
    log.debug('getting boto resource')
    s3 = boto3.resource('s3', **params)
    log.debug('got boto s3 resource: '.format(s3))
    s3object = s3.Object(bucket, key)
    log.debug('got s3 object: {}'.format(s3object))
    s3object.put(Body=data)
    log.debug('object put')
    return True


def read_s3(bucket, key):

    log.info("Downloading config file {0} from s3://{1}...".format(key, bucket))
    s3 = get_s3_resource()
    obj = s3.Object(bucket, key)
    return obj.get()['Body'].read().decode('utf-8')


def get_cookie_vars(headers):

    cooks = get_cookies(headers)
    log.debug('cooks: {}'.format(cooks))
    if 'urs-user-id' in cooks and 'urs-access-token' in cooks:
        return {'urs-user-id': cooks['urs-user-id'], 'urs-access-token': cooks['urs-access-token']}
    else:
        return {}


def do_auth(code, redirect_url):

    url = os.getenv('AUTH_BASE_URL', 'https://urs.earthdata.nasa.gov') + "/oauth/token"

    # App U:P from URS Application
    auth = get_urs_creds()['auth_key']

    post_data = {"grant_type": "authorization_code",
                 "code": code,
                 "redirect_uri": redirect_url}

    headers = {"Authorization": "BASIC " + auth}
    post_data_encoded = urllib.parse.urlencode(post_data).encode("utf-8")
    post_request = urllib.request.Request(url, post_data_encoded, headers)

    try:
        log.debug('headers: {}'.format(headers))
        log.debug('url: {}'.format(url))
        log.debug('post_data: {}'.format(post_data))

        response = urllib.request.urlopen(post_request)
        packet = response.read()
        return json.loads(packet)

    except urllib.error.URLError as e:
        log.error("Error fetching auth: {0}".format(e))
        return False


def cache_session(user_id, token, session):

    global active_sessions                                                             #pylint: disable=global-statement

    log.debug('going to cache {}{} session in lambda memory...'.format(user_id, token))
    session_path = craft_profile_path(user_id, token)
    active_sessions[session_path] = {'profile': session, 'timestamp': round(time.time())}
    log.debug('done caching {}{} session in lambda memory...'.format(user_id, token))

def uncache_session(user_id, token):

    global active_sessions                                                             #pylint: disable=global-statement

    session_path = craft_profile_path(user_id, token)
    try:
        active_sessions.pop(session_path)
    except KeyError:
        # If it's not there, it's not there.
        pass


def prune_cached_sessions():

    # Expire and re-fetch session after 3600 minutes
    pruneable = []
    for pp in active_sessions:
        if active_sessions[pp]['timestamp'] < round(time.time()) - 3600:
            log.debug("Found memory cached profile {0} to be {1} seconds old".format(pp, round(time.time()) -
                                                                                     active_sessions[pp]['timestamp']))
            pruneable.append(pp)
    for pp in pruneable:
        log.debug("Pruning old session: {0}".format(pp))
        active_sessions.pop(pp)


def get_cached_session(user_id, token):

    global active_sessions                                                             #pylint: disable=global-statement

    prune_cached_sessions()

    key = craft_profile_path(user_id, token)
    if key in active_sessions:

        log.debug('wow, returning cached session: {}'.format(key))
        #log.debug('this is it: {}'.format(active_sessions[key]))
        return active_sessions[key]['profile']

    return {}


def get_session(user_id, token):

    sess = get_cached_session(user_id, token)
    if sess:
        return sess

    if session_store == 'DB':
        return get_session_from_db(user_id, token)
    elif session_store == 'S3':
        return get_session_from_s3(user_id, token)


def get_session_from_db(user_id, token):

    session_path = craft_profile_path(user_id, token)
    keydict = {'id': {'S': session_path}}
    resp = ddb.get_item(TableName=sesstable, Key=keydict)
    try:
        session = json.loads(resp['Item']['session']['S'])
        cache_session(user_id, token, session)
        return session
    except KeyError as e:
        log.error('trouble getting session out of table for {} because {}. This is what they gave us: {}'.format(user_id, e, resp))
        return {}


def craft_profile_path(user_id, token):

    return "{0}/{1}".format(user_id, token)


def get_session_from_s3(user_id, token):

    profile_path = craft_profile_path(user_id, token)
    profile = json.loads(read_s3(os.getenv('SESSION_BUCKET', "rain-t-config"), profile_path))
    log.debug("Saving memory cached profile @ {0}".format(profile_path))
    cache_session(user_id, token, profile)
    return profile


def store_session(user_id, token, sess):

    log.debug('storing session into {} for {}: {}'.format(session_store, user_id, sess))
    cache_session(user_id, token, sess)
    log.debug('{}/{} session cached in lambda memory'.format(user_id, token))
    if session_store == 'DB':
        return store_session_in_db(user_id, token, sess)
    elif session_store == 'S3':
        return store_session_in_s3(user_id, token, sess)


def store_session_in_db(user_id, token, sess):

    item = {'id': {'S': '{}/{}'.format(user_id, token)},
            'expires': {'N': str(int(time.time()) + sessttl)},
            'session': {'S': json.dumps(sess)}}
    log.debug('putting {} into table {}'.format(item, sess))
    ddb.put_item(TableName=sesstable, Item=item)
    return True


def store_session_in_s3(user_id, token, user_profile):

    profile_path = craft_profile_path(user_id, token)
    write_s3(os.getenv('SESSION_BUCKET', None), profile_path, json.dumps(user_profile))


def extend_session_ttl(user_id, token):
    if session_store == 'DB':
        return extend_session_ttl_db(user_id, token)
    elif session_store == 'S3':
        return extend_session_ttl_s3(user_id, token)


def extend_session_ttl_db(user_id, token):

    keydict = {'id': {'S': '{}/{}'.format(user_id, token)}}
    updexpr = 'set expires = :e'
    exprattrval = {':e': str(int(time.time()) + sessttl)}
    ddb.update_item(TableName=sesstable, Key=keydict, UpdateExpression=updexpr, ExpressionAttributeValues=exprattrval)


def extend_session_ttl_s3(user_id, token):

    raise NotImplementedError


def delete_session(user_id, token):

    uncache_session(user_id, token)
    if session_store == 'DB':
        return delete_session_db(user_id, token)
    elif session_store == 'S3':
        return delete_session_s3(user_id, token)


def delete_session_db(user_id, token):

    keydict = {'id': {'S': '{}/{}'.format(user_id, token)}}
    resp = ddb.delete_item(TableName=sesstable, Key=keydict)
    log.debug('result from delete: {}'.format(resp))
    return True


def delete_session_s3(user_id, token):

    s3 = get_s3_resource()
    key = craft_profile_path(user_id, token)
    try:
        log.info("Attempting to delete s3 object {0} from s3://{1}...".format(key, os.getenv('SESSION_BUCKET', None)))
        s3.Object(os.getenv('SESSION_BUCKET', None), key).delete()
    except ClientError as e:
        if e.response['Error']['Code'] == "404":
            log.debug("File to delete was not found. Good enough.")
            return True
        else:
            return False
    return True


def get_profile(user_id, token=None, reuse_old_token=None):

    if not user_id:
        return False

    if reuse_old_token:
        refresh_user_profile(user_id)
    else:
        log.info("Getting profile for {0}".format(user_id))

    url = os.getenv('AUTH_BASE_URL', 'https://urs.earthdata.nasa.gov') + "/api/users/{0}".format(user_id)
    headers = {"Authorization": "Bearer " + token}
    req = urllib.request.Request(url, None, headers)

    # check if we're re-using an old token
    cookie_token = reuse_old_token if reuse_old_token else token

    try:
        response = urllib.request.urlopen(req)
        packet = response.read()
        user_profile = json.loads(packet)

        store_session(user_id, cookie_token, user_profile)
        log.debug('{}/{} session stored'.format(user_id, cookie_token))
        return user_profile

    except urllib.error.URLError as e:
        log.error("Error fetching profile: {0}".format(e))
        return False


def get_cookie_expiration_date_str():

    return format_7231_date(time.time() + sessttl)


def check_profile(cookies):

    try:
        token = cookies['urs-access-token']
        user_id = cookies['urs-user-id']
    except(IndexError, KeyError):
        token = False
        user_id = False

    if token and user_id:
        return get_profile(user_id, token)

    else:
        log.warning('Did not find token ({0}) or user_id ({1})'.format(token, user_id))
        return False


def get_role_creds(user_id=None):

    sts = boto3.client('sts')
    if not user_id:
        user_id = 'unauthenticated'
    download_role_arn = os.getenv('EGRESS_APP_DOWNLOAD_ROLE_ARN')
    log.debug('assuming role: {}, role session username: {}'.format(download_role_arn, user_id))
    return sts.assume_role(RoleArn=download_role_arn, RoleSessionName=user_id)


def get_role_session(creds=None, user_id=None):

    sts_resp = creds if creds else get_role_creds(user_id)
    log.debug('sts_resp: {}'.format(sts_resp))
    session = boto3.Session(
        aws_access_key_id=sts_resp['Credentials']['AccessKeyId'],
        aws_secret_access_key=sts_resp['Credentials']['SecretAccessKey'],
        aws_session_token=sts_resp['Credentials']['SessionToken'])

    return session


def hmacsha256 (key, string):

    return hmac.new( key, string.encode('utf-8'), hashlib.sha256 )


def get_presigned_url(session, bucket_name, object_name, region_name, expire_seconds, user_id):

    timez = datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
    datez = timez[:8]
    hostname = "{0}.s3{1}.amazonaws.com".format(bucket_name, "."+region_name if region_name != "us-east-1" else "")

    cred   = session['Credentials']['AccessKeyId']
    secret = session['Credentials']['SecretAccessKey']
    token  = session['Credentials']['SessionToken']

    aws4_request = "/".join([datez, region_name, "s3", "aws4_request"])
    cred_string = "{0}/{1}".format(cred, aws4_request)

    # Canonical Query String Parts
    parts = ["A-userid={0}".format(user_id),
             "X-Amz-Algorithm=AWS4-HMAC-SHA256",
             "X-Amz-Credential="+urllib.parse.quote_plus(cred_string),
             "X-Amz-Date="+timez,
             "X-Amz-Expires={0}".format(expire_seconds),
             "X-Amz-Security-Token="+urllib.parse.quote_plus(token),
             "X-Amz-SignedHeaders=host"]

    can_query_string = "&".join(parts)

    # Canonical Requst
    can_req = "GET" + "\n/" + object_name + "\n" + can_query_string + "\nhost:" + hostname + "\n\nhost\nUNSIGNED-PAYLOAD"
    can_req_hash = hashlib.sha256(can_req.encode('utf-8')).hexdigest()

    # String to Sign
    stringtosign = "\n".join(["AWS4-HMAC-SHA256", timez, aws4_request, can_req_hash])

    # Signing Key
    StepOne =    hmacsha256( "AWS4{0}".format(secret).encode('utf-8'), datez).digest()
    StepTwo =    hmacsha256( StepOne, region_name ).digest()
    StepThree =  hmacsha256( StepTwo, "s3").digest()
    SigningKey = hmacsha256( StepThree, "aws4_request").digest()


    # Final Signature
    Signature = hmacsha256(SigningKey, stringtosign).hexdigest()

    # Dump URL
    url = "https://" + hostname + "/" + object_name + "?" + can_query_string + "&X-Amz-Signature=" + Signature
    return url


def get_bucket_dynamic_path(path_list, b_map):

    # Old and REVERSE format has no 'MAP'. In either case, we don't want it fouling our dict.
    if 'MAP' in b_map:
        derived = b_map['MAP']
    else:
        derived = b_map

    mapping = []

    log.debug("Pathparts is {0}".format(", ".join(path_list)))

    # walk the bucket map to see if this path is valid
    for path_part in path_list:

        # Check if we hit a leaf of the YAML tree
        if len(mapping) > 0 and isinstance(derived, str):

            # Pop mapping off path_list
            for _ in mapping:
               path_list.pop(0)

            # Join the remaining bits together to form object_name
            object_name = "/".join(path_list)
            bucket_path = "/".join(mapping)

            log.info("Bucket mapping was {0}, object was {1}".format(bucket_path, object_name))
            return prepend_bucketname(derived), bucket_path, object_name

        if path_part in derived:
            derived = derived[path_part]
            mapping.append(path_part)
            log.debug("Found {0}, Mapping is now {1}".format(path_part, "/".join(mapping)))

        else:
            log.warning("Could not find {0} in bucketmap".format(path_part))
            log.debug('said bucketmap: {}'.format(derived))
            return False, False, False

    # what? No path?
    return False, False, False


def process_varargs(varargs, b_map):

    varargs = varargs.split("/")

    # Make sure we got atleast 1 path, and 1 file name:
    if len(varargs) < 2:
        return "/".join(varargs), None, None

    # Watch for ASF-ish reverse URL mapping formats:
    if len(varargs) == 3:
        if os.getenv('USE_REVERSE_BUCKET_MAP', 'FALSE').lower() == 'true':
            varargs[0], varargs[1] = varargs[1], varargs[0]

    # Look up the bucket from path parts
    bucket, path, object_name  = get_bucket_dynamic_path(varargs, b_map)

    # If we didn't figure out the bucket, we don't know the path/object_name
    if not bucket:
        object_name = varargs.pop(-1)
        path = "/".join(varargs)

    return path, bucket, object_name


def user_in_group(private_groups, cookievars, user_profile=None, refresh_first=False):

    if not private_groups:
        return False

    user_id = cookievars['urs-user-id']
    token = cookievars['urs-access-token']

    # initially, we want to try to see if the user is in the group before refresh
    if refresh_first or not user_profile:
        user_profile = get_profile(user_id, token, True)

    # check if the use has one of the groups from the private group list

    if 'user_groups' in user_profile:
        client_id = get_urs_creds()['client_id']
        log.info ("Searching for private groups {0} in {1}".format( private_groups, user_profile['user_groups']))
        for u_g in user_profile['user_groups']:
            if u_g['client_id'] == client_id:
                for p_g in private_groups:
                    if p_g == u_g['name']:
                        # Found the matching group!
                        log.info("User {0} belongs to private group {1}".format(user_id, p_g))
                        return True

    # User likely isn't in ANY groups
    else:
       log.warning('user_groups block not found in user profile!')

    if not refresh_first:
        # maybe refreshing the user's profile will help
        log.info("Could not validate user {0} belonging to groups {1}, attempting profile refresh".format(user_id, private_groups))
        return user_in_group(private_groups, cookievars, refresh_first=True)

    log.warning("Even after profile fresh, user {0} does not below to groups {1}".format(user_id, private_groups))
    return False


def prepend_bucketname(name):

    prefix = os.getenv('BUCKETNAME_PREFIX', "gsfc-ngap-{}-".format(os.getenv('MATURITY', 'DEV')[0:1].lower()))
    return "{}{}".format(prefix, name)


def check_private_bucket(bucket, private_buckets, b_map):

    log.debug('check_private_buckets(): bucket: {}, private_buckets: {}'.format(bucket, private_buckets))

    # Check public bucket file:
    if private_buckets and 'PRIVATE_BUCKETS' in private_buckets:
        for priv_bucket in private_buckets['PRIVATE_BUCKETS']:
            if bucket == prepend_bucketname(priv_bucket):
                # This bucket is PRIVATE, return group!
                return private_buckets['PRIVATE_BUCKETS'][priv_bucket]

    # Check public bucket file:
    if 'PRIVATE_BUCKETS' in b_map:
        for priv_bucket in b_map['PRIVATE_BUCKETS']:
            if bucket == prepend_bucketname(priv_bucket):
                # This bucket is PRIVATE, return group!
                return b_map['PRIVATE_BUCKETS'][bucket][priv_bucket]

    return False


def check_public_bucket(bucket, public_buckets, b_map):
    # Check public bucket file:
    if 'PUBLIC_BUCKETS' in public_buckets:
        log.debug('we have a PUBLIC_BUCKETS in the public buckets file')
        for pub_bucket in public_buckets['PUBLIC_BUCKETS']:
            #log.debug('is {} the same as {}?'.format(bucket, prepend_bucketname(pub_bucket)))
            if bucket == prepend_bucketname(pub_bucket):
                # This bucket is public!
                log.debug('found a public, we\'ll take it')
                return True

    # Check for PUBLIC_BUCKETS in bucket map file
    if 'PUBLIC_BUCKETS' in b_map:
        log.debug('we have a PUBLIC_BUCKETS in the ordinary bucketmap file')
        for pub_bucket in b_map['PUBLIC_BUCKETS']:
            #log.debug('is {} the same as {}?'.format(bucket, prepend_bucketname(pub_bucket)))
            if bucket == prepend_bucketname(pub_bucket):
                # This bucket is public!
                log.debug('found a public, we\'ll take it')
                return True

    # Did not find this in public bucket list
    log.debug('we did not find a public bucket for {}'.format(bucket))
    return False


def get_cookies(hdrs):

    cookies = {}
    pre_cookies = []
    if 'cookie' in hdrs:
        pre_cookies = hdrs['cookie'].split(';')
        for cook in pre_cookies:
            # print('x: {}'.format(cook))
            splitcook = cook.split('=')
            cookies.update({splitcook[0].strip(): splitcook[1].strip()})

    return cookies


def refresh_user_profile(user_id):

    # get a new token
    url = os.getenv('AUTH_BASE_URL', 'https://urs.earthdata.nasa.gov') + "/oauth/token"

    # App U:P from URS Application
    auth = get_urs_creds()['auth_key']
    post_data = {"grant_type": "client_credentials" }
    headers = {"Authorization": "BASIC " + auth}

    # Download token
    post_data_encoded = urllib.parse.urlencode(post_data).encode("utf-8")
    post_request = urllib.request.Request(url, post_data_encoded, headers)

    try:
        log.info("Attempting to get new Token")
        response = urllib.request.urlopen(post_request)
        packet = response.read()
        new_token = json.loads(packet)['access_token']
        log.info("Retrieved new token: {0}".format(new_token))

        # Get user profile with new token
        return get_profile(new_token, user_id)

    except urllib.error.URLError as e:
        log.error("Error fetching auth: {0}".format(e))
        return False


def get_html_body(template_vars:dict, templatefile:str='root.html'):
    jin_env = Environment(
        loader=FileSystemLoader([os.path.join(os.path.dirname(__file__), "templates")]),
        autoescape=select_autoescape(['html', 'xml'])
    )
    jin_tmp = jin_env.get_template(templatefile)
    return jin_tmp.render(**template_vars)


# return looks like:
# {
#     "client_id": "stringofseeminglyrandomcharacters",
#     "auth_key": "verymuchlongerstringofseeminglyrandomcharacters"
# }
def get_urs_creds():

    secret_name = os.getenv('URS_CREDS_SECRET_NAME', None)
    region_name = os.getenv('AWS_DEFAULT_REGION')

    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )

    # In this sample we only handle the specific exceptions for the 'GetSecretValue' API.
    # See https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
    # We rethrow the exception by default.

    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
        if e.response['Error']['Code'] == 'DecryptionFailureException':
            # Secrets Manager can't decrypt the protected secret text using the provided KMS key.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InternalServiceErrorException':
            # An error occurred on the server side.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            # You provided an invalid value for a parameter.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            # You provided a parameter value that is not valid for the current state of the resource.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'ResourceNotFoundException':
            # We can't find the resource that you asked for.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
    else:
        # Decrypts secret using the associated KMS CMK.
        # Depending on whether the secret is a string or binary, one of these fields will be populated.
        #log.debug(get_secret_value_response)
        if 'SecretString' in get_secret_value_response:
            secret = json.loads(get_secret_value_response['SecretString'])
            #log.debug('secret: {}'.format(secret))
            return secret
        else:
            # We probably wouldn't get here since we're storing text data, right?
            return {}
            #decoded_binary_secret = base64.b64decode(get_secret_value_response['SecretBinary'])
            #log.debug('decoded_binary_secret: '.format(decoded_binary_secret))
            #return decoded_binary_secret
    # Your code goes here.
