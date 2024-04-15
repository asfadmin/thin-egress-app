import base64
import contextlib
import io
from unittest import mock
from urllib.error import HTTPError

import chalice
import pytest
import yaml
from botocore.exceptions import ClientError
from chalice.test import Client
from rain_api_core.auth import UserProfile

from thin_egress_app import app

MODULE = "thin_egress_app.app"


@pytest.fixture
def user_profile():
    return UserProfile(
        user_id="test_user",
        first_name="John",
        last_name="Smith",
        email="j.smith@email.com",
        groups=[
            {
                "group_id": "group_uuid",
                "name": "restricted",
                "tag": None,
                "shared_user_group": False,
                "created_by": "egress_download_app",
                "app_uid": "egress_download_app",
                "client_id": "client_id"
            }
        ],
        token="test_token",
        iat=0,
        exp=0
    )


@pytest.fixture
def _clear_caches():
    app.get_bc_config_client.cache_clear()
    app.get_bucket_region_cache.clear()


@pytest.fixture(scope="module")
def client():
    return Client(app.app)


@pytest.fixture
def lambda_context():
    ctx = mock.Mock()
    app.app.lambda_context = ctx
    yield ctx
    del app.app.lambda_context


@pytest.fixture
def current_request(lambda_context):
    lambda_context.aws_request_id = "request_1234"
    req = mock.MagicMock()
    app.app.current_request = req
    yield req
    del app.app.current_request


@pytest.fixture
def mock_retrieve_secret():
    with mock.patch(f"{MODULE}.retrieve_secret", autospec=True) as m:
        m.return_value = {
            "rsa_pub_key": base64.b64encode(b"pub-key").decode(),
            "rsa_priv_key": base64.b64encode(b"priv-key").decode()
        }
        yield m


@pytest.fixture
def mock_get_urs_creds():
    with mock.patch(f"{MODULE}.get_urs_creds", autospec=True) as m:
        m.return_value = {
            "UrsId": "stringofseeminglyrandomcharacters",
            "UrsAuth": "verymuchlongerstringofseeminglyrandomcharacters"
        }
        yield m


@pytest.fixture
def mock_get_urs_url():
    with mock.patch(f"{MODULE}.get_urs_url", autospec=True) as m:
        m.return_value = "https://urs.example.domain?redirect=oururl"
        yield m


@pytest.fixture
def mock_make_html_response():
    with mock.patch(f"{MODULE}.TEMPLATE_MANAGER", autospec=True) as mgr:
        original_make_html_response = app.make_html_response
        with mock.patch(f"{MODULE}.make_html_response", autospec=True) as m:
            mgr.render.return_value = "Mock response"
            m.side_effect = original_make_html_response
            yield m


@pytest.fixture
def mock_request():
    with mock.patch(f"{MODULE}.request", autospec=True) as m:
        yield m


@mock.patch(f"{MODULE}.urllib.request", autospec=True)
def test_update_blacklist(mock_request, monkeypatch):
    endpoint = "https://blacklist.com"
    monkeypatch.setenv("BLACKLIST_ENDPOINT", endpoint)
    mock_request.urlopen(endpoint).read.return_value = b'{"blacklist": {"foo": "bar"}}'
    assert app.get_black_list() == {"foo": "bar"}


def test_request_authorizer_no_headers(current_request, mock_get_urs_url):
    current_request.headers = {}
    current_request.context = {"path": "/foo"}
    authorizer = app.RequestAuthorizer()

    assert authorizer.get_profile() is None
    response = authorizer.get_error_response()
    assert response is not None
    assert response.body == ""
    assert response.status_code == 302
    assert authorizer.get_success_response_headers() == {}


@mock.patch(f"{MODULE}.get_user_from_token", autospec=True)
@mock.patch(f"{MODULE}.get_new_token_and_profile", autospec=True)
def test_request_authorizer_bearer_header(mock_get_new_token_and_profile, mock_get_user_from_token, current_request):
    current_request.headers = {
        "Authorization": "Bearer token",
        "x-origin-request-id": "origin_request_id"
    }
    mock_user_profile = mock.Mock()
    mock_get_new_token_and_profile.return_value = mock_user_profile
    mock_get_user_from_token.return_value = "user_name"

    authorizer = app.RequestAuthorizer()

    assert authorizer.get_profile() == mock_user_profile
    mock_get_new_token_and_profile.assert_called_once_with(
        "user_name",
        True,
        aux_headers={
            "x-request-id": "request_1234",
            "x-origin-request-id": "origin_request_id"
        }
    )


@mock.patch(f"{MODULE}.do_auth_and_return", autospec=True)
def test_request_authorizer_basic_header(mock_do_auth_and_return, current_request):
    current_request.headers = {
        "Authorization": "Basic token",
        "x-origin-request-id": "origin_request_id"
    }
    mock_response = mock.Mock()
    mock_do_auth_and_return.return_value = mock_response

    authorizer = app.RequestAuthorizer()

    assert authorizer.get_profile() is None
    assert authorizer.get_error_response() == mock_response


@mock.patch(f"{MODULE}.get_user_from_token", autospec=True)
def test_request_authorizer_bearer_header_eula_error(mock_get_user_from_token, current_request):
    current_request.headers = {"Authorization": "Bearer token"}
    mock_get_user_from_token.side_effect = app.EulaException({})

    authorizer = app.RequestAuthorizer()

    assert authorizer.get_profile() is None

    response = authorizer.get_error_response()
    assert response.status_code == 403
    assert response.headers == {}


@mock.patch(f"{MODULE}.get_user_from_token", autospec=True)
def test_request_authorizer_bearer_header_eula_error_browser(
    mock_get_user_from_token,
    mock_make_html_response,
    current_request
):
    current_request.headers = {
        "Authorization": "Bearer token",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    }
    mock_get_user_from_token.side_effect = app.EulaException({
        "status_code": 403,
        "error_description": "EULA Acceptance Failure",
        "resolution_url": "http://resolution_url"
    })

    authorizer = app.RequestAuthorizer()

    assert authorizer.get_profile() is None

    response = authorizer.get_error_response()
    mock_make_html_response.assert_called_once_with(
        {
            "title": "EULA Acceptance Failure",
            "status_code": 403,
            "contentstring": (
                'Could not fetch data because "EULA Acceptance Failure". Please accept EULA here: '
                '<a href="http://resolution_url">http://resolution_url</a> and try again.'
            ),
            "requestid": "request_1234",
        },
        {},
        403,
        "error.html"
    )
    assert response.status_code == 403
    assert response.headers == {"Content-Type": "text/html"}


@mock.patch(f"{MODULE}.get_user_from_token", autospec=True)
@mock.patch(f"{MODULE}.get_new_token_and_profile", autospec=True)
@mock.patch(f"{MODULE}.do_auth_and_return", autospec=True)
def test_request_authorizer_bearer_header_no_profile(
    mock_do_auth_and_return,
    mock_get_new_token_and_profile,
    mock_get_user_from_token,
    current_request
):
    current_request.headers = {
        "Authorization": "Bearer token",
        "x-origin-request-id": "origin_request_id"
    }
    mock_response = mock.Mock()
    mock_do_auth_and_return.return_value = mock_response
    mock_get_new_token_and_profile.return_value = False
    mock_get_user_from_token.return_value = "user_name"

    authorizer = app.RequestAuthorizer()

    assert authorizer.get_profile() is None
    assert authorizer.get_error_response() == mock_response
    mock_get_new_token_and_profile.assert_called_once_with(
        "user_name",
        True,
        aux_headers={
            "x-request-id": "request_1234",
            "x-origin-request-id": "origin_request_id"
        }
    )
    mock_do_auth_and_return.assert_called_once_with(current_request.context)


@mock.patch(f"{MODULE}.get_user_from_token", autospec=True)
@mock.patch(f"{MODULE}.do_auth_and_return", autospec=True)
def test_request_authorizer_bearer_header_no_user_id(
    mock_do_auth_and_return,
    mock_get_user_from_token,
    current_request
):
    current_request.headers = {
        "Authorization": "Bearer token",
        "x-origin-request-id": "origin_request_id"
    }
    mock_response = mock.Mock()
    mock_do_auth_and_return.return_value = mock_response
    mock_get_user_from_token.return_value = None

    authorizer = app.RequestAuthorizer()

    assert authorizer.get_profile() is None
    assert authorizer.get_error_response() == mock_response
    mock_do_auth_and_return.assert_called_once_with(current_request.context)


def test_get_request_id(lambda_context):
    lambda_context.aws_request_id = "1234"
    assert app.get_request_id() == "1234"


def test_get_origin_request_id(current_request):
    current_request.headers = {}
    assert app.get_origin_request_id() is None

    current_request.headers["x-origin-request-id"] = "1234"
    assert app.get_origin_request_id() == "1234"


def test_get_aux_request_headers(current_request):
    current_request.headers = {}
    assert app.get_aux_request_headers() == {"x-request-id": "request_1234"}

    current_request.headers = {"x-origin-request-id": "1234"}
    assert app.get_aux_request_headers() == {"x-request-id": "request_1234", "x-origin-request-id": "1234"}


def test_check_for_browser():
    FIREFOX_UA = "Mozilla/5.0 (X11; Linux x86_64; rv:93.0) Gecko/20100101 Firefox/93.0"
    CHROME_UA = "Mozilla/5.0 (X11; CrOS x86_64 13982.82.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.157 Safari/537.36 "  # noqa
    EDGE_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4501.0 Safari/537.36 Edg/91.0.866.0"  # noqa
    BINGBOT_UA = "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)"

    assert app.check_for_browser({}) is False
    assert app.check_for_browser({"user-agent": FIREFOX_UA}) is True
    assert app.check_for_browser({"user-agent": CHROME_UA}) is True
    assert app.check_for_browser({"user-agent": EDGE_UA}) is True
    assert app.check_for_browser({"user-agent": BINGBOT_UA}) is True
    assert app.check_for_browser({"user-agent": "Not a valid user agent"}) is False


def test_get_user_from_token(mock_request, mock_get_urs_creds, current_request):
    del current_request

    payload = '{"uid": "user_name"}'
    mock_response = mock.Mock()
    mock_response.read.return_value = payload
    mock_response.code = 200
    mock_request.urlopen.return_value = mock_response

    assert app.get_user_from_token("token") == "user_name"
    mock_get_urs_creds.assert_called_once()


def test_get_user_from_token_eula_error(mock_request, mock_get_urs_creds, current_request):
    del current_request

    payload = """{
        "status_code": 403,
        "error_description": "EULA Acceptance Failure",
        "resolution_url": "http://uat.urs.earthdata.nasa.gov/approve_app?client_id=asdf"
    }
    """
    mock_request.urlopen.side_effect = HTTPError("", 403, "Forbidden", {}, io.StringIO(payload))

    with pytest.raises(app.EulaException):
        app.get_user_from_token("token")
    mock_get_urs_creds.assert_called_once()


def test_get_user_from_token_other_error(mock_request, mock_get_urs_creds, current_request):
    del current_request

    payload = """{
        "status_code": 401,
        "error": "some error",
        "error_description": "some error description"
    }
    """
    mock_request.urlopen.side_effect = HTTPError("", 401, "Bad Request", {}, io.StringIO(payload))

    assert app.get_user_from_token("token") is None
    mock_get_urs_creds.assert_called_once()


@pytest.mark.parametrize("code", (200, 403, 500))
def test_get_user_from_token_json_error(mock_request, mock_get_urs_creds, current_request, code):
    del current_request

    mock_request.urlopen.side_effect = HTTPError("", code, "Message", {}, io.StringIO("not valid json"))

    assert app.get_user_from_token("token") is None
    mock_get_urs_creds.assert_called_once()


def test_cumulus_log_message(current_request):
    del current_request

    strio = io.StringIO()
    with contextlib.redirect_stdout(strio):
        app.cumulus_log_message("outcome", 200, "GET", {"foo": "bar"})

    assert strio.getvalue() == (
        '{"foo": "bar", "code": 200, "http_method": "GET", "status": "outcome", "requestid": "request_1234"}\n'
    )


@mock.patch(f"{MODULE}.get_yaml_file", autospec=True)
def test_restore_bucket_vars(mock_get_yaml_file, data_path):
    with open(data_path / "bucket_map_example.yaml") as f:
        buckets = yaml.full_load(f)

    mock_get_yaml_file.return_value = buckets
    app.b_map = None

    app.restore_bucket_vars()

    assert app.b_map.bucket_map == buckets


@mock.patch(f"{MODULE}.get_yaml_file", autospec=True)
def test_restore_bucket_vars_iam_compatibility_error(
    mock_get_yaml_file,
    monkeypatch
):
    mock_get_yaml_file.return_value = {
        "PATH": "bucket",
        "PRIVATE_BUCKETS": {
            "bucket/prefix/": ["group"]
        }
    }

    app.b_map = None
    monkeypatch.setenv("ENABLE_S3_CREDENTIALS_ENDPOINT", "False")
    app.restore_bucket_vars()

    app.b_map = None
    monkeypatch.setenv("ENABLE_S3_CREDENTIALS_ENDPOINT", "True")
    with pytest.raises(ValueError, match="Invalid prefix permissions"):
        app.restore_bucket_vars()


@mock.patch(f"{MODULE}.get_urs_url", autospec=True)
def test_do_auth_and_return(mock_get_urs_url, monkeypatch):
    mock_get_urs_url.side_effect = lambda _ctx, redirect: redirect

    response = app.do_auth_and_return({"path": "/some/path"})
    assert response.body == ""
    assert response.status_code == 302
    assert response.headers == {"Location": "%2Fsome%2Fpath"}

    monkeypatch.setenv("DOMAIN_NAME", "www.example.com")

    response = app.do_auth_and_return({"path": "/some/other/path"})
    assert response.body == ""
    assert response.status_code == 302
    assert response.headers == {"Location": "%2Fsome%2Fother%2Fpath"}

    response = app.do_auth_and_return({"path": "/DEV/some/path"})
    assert response.body == ""
    assert response.status_code == 302
    assert response.headers == {"Location": "%2Fsome%2Fpath"}


def test_add_cors_headers(current_request, monkeypatch):
    current_request.headers = {}
    headers = {"foo": "bar"}
    app.add_cors_headers(headers)
    assert headers == {"foo": "bar"}

    monkeypatch.setenv("CORS_ORIGIN", "example.com")

    current_request.headers = {"origin": "NULL"}
    headers = {"foo": "bar"}
    app.add_cors_headers(headers)
    assert headers == {
        "foo": "bar",
        "Access-Control-Allow-Origin": "NULL",
        "Access-Control-Allow-Credentials": "true"
    }

    current_request.headers = {"origin": "foo.example.com"}
    headers = {"foo": "bar"}
    app.add_cors_headers(headers)
    assert headers == {
        "foo": "bar",
        "Access-Control-Allow-Origin": "foo.example.com",
        "Access-Control-Allow-Credentials": "true"
    }

    current_request.headers = {"origin": "foo.bar.com"}
    headers = {"foo": "bar"}
    app.add_cors_headers(headers)
    assert headers == {"foo": "bar"}


def test_make_redirect(current_request):
    current_request.headers = {}

    response = app.make_redirect("www.example.com")
    assert response.body == ""
    assert response.headers == {"Location": "www.example.com"}
    assert response.status_code == 301

    response = app.make_redirect("www.example.com", headers={"foo": "bar"})
    assert response.body == ""
    assert response.headers == {"foo": "bar", "Location": "www.example.com"}
    assert response.status_code == 301


def test_make_html_response(monkeypatch):
    mock_render = mock.Mock(return_value="<html></html>")
    monkeypatch.setattr(f"{MODULE}.TEMPLATE_MANAGER.render", mock_render)

    response = app.make_html_response({"foo": "bar"}, {"baz": "qux"})
    assert response.body == "<html></html>"
    assert response.status_code == 200
    assert response.headers == {"Content-Type": "text/html", "baz": "qux"}
    mock_render.assert_called_once_with("root.html", {"STAGE": "DEV", "status_code": 200, "foo": "bar"})
    mock_render.reset_mock()

    monkeypatch.setenv("DOMAIN_NAME", "example.com")
    response = app.make_html_response({}, {}, 301, "redirect.html")
    assert response.body == "<html></html>"
    assert response.status_code == 301
    assert response.headers == {"Content-Type": "text/html"}
    mock_render.assert_called_once_with("redirect.html", {"STAGE": None, "status_code": 301})


def test_get_bcconfig(monkeypatch):
    assert app.get_bcconfig("some_user_id") == {
        "user_agent": "Thin Egress App for userid=some_user_id",
        "s3": {"addressing_style": "path"},
        "connect_timeout": 600,
        "read_timeout": 600,
        "retries": {"max_attempts": 10}
    }

    monkeypatch.setenv("S3_SIGNATURE_VERSION", "some_s3_signature")
    assert app.get_bcconfig("another_user_id") == {
        "user_agent": "Thin Egress App for userid=another_user_id",
        "s3": {"addressing_style": "path"},
        "connect_timeout": 600,
        "read_timeout": 600,
        "retries": {"max_attempts": 10},
        "signature_version": "some_s3_signature"
    }

    monkeypatch.setenv("S3_SIGNATURE_VERSION", "")
    assert app.get_bcconfig("another_user_id") == {
        "user_agent": "Thin Egress App for userid=another_user_id",
        "s3": {"addressing_style": "path"},
        "connect_timeout": 600,
        "read_timeout": 600,
        "retries": {"max_attempts": 10}
    }


def test_get_bucket_region():
    session = mock.Mock()
    session.client().get_bucket_location.return_value = {"LocationConstraint": "us-west-2"}
    assert app.get_bucket_region(session, "bucketname") == "us-west-2"

    session.client.side_effect = ClientError({}, "bar")
    with pytest.raises(ClientError):
        app.get_bucket_region(session, "bucketname2")


def test_get_bucket_region_cached(_clear_caches):
    session = mock.Mock()
    session.client().get_bucket_location.return_value = {"LocationConstraint": "us-west-2"}
    assert app.get_bucket_region(session, "bucketname") == "us-west-2"
    assert app.get_bucket_region(session, "bucketname") == "us-west-2"
    assert app.get_bucket_region(session, "bucketname") == "us-west-2"
    session.client().get_bucket_location.assert_called_once()


def test_get_user_ip(current_request):
    current_request.headers = {"x-forwarded-for": "10.0.0.1"}
    assert app.get_user_ip() == "10.0.0.1"

    current_request.headers = {"x-forwarded-for": "10. 0. 0. 1"}
    assert app.get_user_ip() == "10.0.0.1"

    current_request.headers = {"x-forwarded-for": "10.0.0.1,192.168.0.1"}
    assert app.get_user_ip() == "10.0.0.1"

    current_request.headers = {}
    current_request.context = {"identity": {"sourceIp": "10.0.0.1"}}
    assert app.get_user_ip() == "10.0.0.1"


@mock.patch(f"{MODULE}.check_in_region_request", autospec=True)
@mock.patch(f"{MODULE}.get_role_creds", autospec=True)
@mock.patch(f"{MODULE}.get_role_session", autospec=True)
@mock.patch(f"{MODULE}.get_presigned_url", autospec=True)
@mock.patch(f"{MODULE}.b_map", None)
def test_try_download_from_bucket(
    mock_get_presigned_url,
    mock_get_role_session,
    mock_get_role_creds,
    mock_check_in_region_request,
    current_request,
    monkeypatch,
    user_profile
):
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.setenv("CORS_ORIGIN", "example.com")
    current_request.headers = {"origin": "example.com"}
    mock_get_role_creds.return_value = (mock.Mock(), 1000)
    presigned_url = "somebucket.s3.us-west-2.amazonaws.com"
    mock_get_presigned_url.return_value = presigned_url
    client = mock_get_role_session().client()
    client.get_bucket_location.return_value = {"LocationConstraint": "us-east-1"}
    client.head_object.return_value = {"ContentLength": 2048}

    response = app.try_download_from_bucket("somebucket", "somefile", user_profile, {}, api_request_uuid=None)
    client.head_object.assert_called_once()
    assert response.body == ""
    assert response.status_code == 303
    assert response.headers == {
        "Location": presigned_url,
        "Cache-Control": "private, max-age=2540",
        "Access-Control-Allow-Origin": "example.com",
        "Access-Control-Allow-Credentials": "true"
    }
    mock_check_in_region_request.assert_called_once()

    # Hit some of the other code paths
    monkeypatch.setenv("SUPPRESS_HEAD", "1")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-west-2")
    client.head_object.reset_mock()

    response = app.try_download_from_bucket("somebucket", "somefile", user_profile, "not a dict", api_request_uuid=None)
    client.head_object.assert_not_called()
    assert response.body == ""
    assert response.status_code == 303
    assert response.headers == {
        "Location": presigned_url,
        "Cache-Control": "private, max-age=2540",
        "Access-Control-Allow-Origin": "example.com",
        "Access-Control-Allow-Credentials": "true"
    }


@mock.patch(f"{MODULE}.check_in_region_request", autospec=True)
@mock.patch(f"{MODULE}.get_role_creds", autospec=True)
@mock.patch(f"{MODULE}.get_role_session", autospec=True)
def test_try_download_from_bucket_client_error(
    mock_get_role_session,
    mock_get_role_creds,
    mock_check_in_region_request,
    mock_make_html_response,
    current_request,
    _clear_caches,
    user_profile
):
    del current_request

    mock_get_role_creds.return_value = (mock.Mock(), 1000)
    mock_get_role_session().client.side_effect = ClientError({}, "bar")

    app.try_download_from_bucket("somebucket", "somefile", user_profile, {}, None)
    mock_make_html_response.assert_called_once_with(
        {
            "contentstring": "There was a problem accessing download data.",
            "title": "Data Not Available",
            "requestid": "request_1234",
        },
        {},
        400,
        "error.html"
    )
    mock_check_in_region_request.assert_called_once()


@mock.patch(f"{MODULE}.check_in_region_request", autospec=True)
@mock.patch(f"{MODULE}.get_role_creds", autospec=True)
@mock.patch(f"{MODULE}.get_role_session", autospec=True)
@mock.patch(f"{MODULE}.get_bc_config_client", autospec=True)
def test_try_download_from_bucket_not_found(
    mock_get_bc_config_client,
    mock_get_role_session,
    mock_get_role_creds,
    mock_check_in_region_request,
    mock_make_html_response,
    current_request,
    monkeypatch,
    user_profile
):
    del current_request

    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    mock_get_role_creds.return_value = (mock.Mock(), 1000)
    mock_get_bc_config_client(None).head_object.side_effect = ClientError(
        {"ResponseMetadata": {"HTTPStatusCode": 404}},
        "bar"
    )

    app.try_download_from_bucket("somebucket", "somefile", user_profile, {}, None)
    mock_make_html_response.assert_called_once_with(
        {
            "contentstring": "Could not find requested data.",
            "title": "Data Not Available",
            "requestid": "request_1234",
        },
        {},
        404,
        "error.html"
    )
    mock_get_role_creds.assert_called_once()
    mock_get_role_session.assert_called_once()
    mock_check_in_region_request.assert_called_once()


@mock.patch(f"{MODULE}.check_in_region_request", autospec=True)
@mock.patch(f"{MODULE}.get_role_creds", autospec=True)
@mock.patch(f"{MODULE}.get_role_session", autospec=True)
@mock.patch(f"{MODULE}.get_bc_config_client", autospec=True)
def test_try_download_from_bucket_invalid_range(
    mock_get_bc_config_client,
    mock_get_role_session,
    mock_get_role_creds,
    mock_check_in_region_request,
    current_request,
    monkeypatch,
    user_profile
):
    del current_request

    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    mock_get_role_creds.return_value = (mock.Mock(), 1000)
    mock_get_bc_config_client(None).head_object.side_effect = ClientError(
        {"ResponseMetadata": {"HTTPStatusCode": 416}},
        "bar"
    )

    response = app.try_download_from_bucket("somebucket", "somefile", user_profile, {}, None)
    assert response.body == "Invalid Range"
    assert response.status_code == 416
    assert response.headers == {}
    mock_get_role_creds.assert_called_once()
    mock_get_role_session.assert_called_once()
    mock_check_in_region_request.assert_called_once()


@mock.patch(f"{MODULE}.JWT_COOKIE_NAME", "asf-cookie")
def test_get_jwt_field():
    assert app.get_jwt_field({"asf-cookie": {"foo": "bar"}}, "foo") == "bar"
    assert app.get_jwt_field({"asf-cookie": {}}, "foo") is None
    assert app.get_jwt_field({}, "foo") is None


@mock.patch(f"{MODULE}.get_urs_url", autospec=True)
def test_root(mock_get_urs_url, mock_retrieve_secret, mock_make_html_response, client):
    del mock_retrieve_secret

    urs_url = "urs.example.com"
    mock_get_urs_url.return_value = urs_url

    client.http.get("/")

    mock_make_html_response.assert_called_once_with(
        {
            "title": "Welcome",
            "URS_URL": "urs.example.com"
        },
        {"Content-Type": "text/html"},
        200,
        "root.html"
    )


@mock.patch(f"{MODULE}.get_urs_url", autospec=True)
@mock.patch(f"{MODULE}.JwtManager.get_profile_from_headers", autospec=True)
def test_root_with_login(
    mock_get_profile,
    mock_get_urs_url,
    mock_retrieve_secret,
    mock_make_html_response,
    monkeypatch,
    client,
    user_profile
):
    del mock_retrieve_secret

    monkeypatch.setenv("MATURITY", "DEV")
    mock_get_profile.return_value = user_profile

    client.http.get("/")

    mock_get_urs_url.assert_not_called()
    mock_make_html_response.assert_called_once_with(
        {
            "title": "Welcome",
            "profile": {
                "urs-user-id": "test_user",
                "urs-access-token": "test_token",
                "urs-groups": [
                    {
                        "group_id": "group_uuid",
                        "name": "restricted",
                        "tag": None,
                        "shared_user_group": False,
                        "created_by": "egress_download_app",
                        "app_uid": "egress_download_app",
                        "client_id": "client_id"
                    }
                ],
                "first_name": "John",
                "last_name": "Smith",
                "email": "j.smith@email.com",
                "iat": 0,
                "exp": 0
            }
        },
        {"Content-Type": "text/html"},
        200,
        "root.html"
    )

    # There is no profile
    mock_make_html_response.reset_mock()
    mock_get_profile.return_value = None
    mock_get_urs_url.return_value = "urs_url"

    client.http.get("/")

    mock_get_urs_url.assert_called_once()
    mock_make_html_response.assert_called_once_with(
        {"title": "Welcome", "URS_URL": "urs_url"},
        {"Content-Type": "text/html"},
        200,
        "root.html"
    )


@mock.patch(f"{MODULE}.get_urs_url", autospec=True)
@mock.patch(f"{MODULE}.JwtManager.get_header_to_set_auth_cookie", autospec=True)
@mock.patch(f"{MODULE}.JwtManager.get_profile_from_headers", autospec=True)
@mock.patch(f"{MODULE}.JWT_COOKIE_NAME", "asf-cookie")
def test_logout(
    mock_get_profile,
    mock_get_header_to_set_auth_cookie,
    mock_get_urs_url,
    mock_retrieve_secret,
    mock_make_html_response,
    user_profile,
    client
):
    del mock_retrieve_secret

    mock_get_urs_url.return_value = "urs_url"
    mock_get_profile.return_value = user_profile
    mock_get_header_to_set_auth_cookie.return_value = {"asf-cookie": {}}

    client.http.get("/logout")

    mock_make_html_response.assert_called_once_with(
        {
            "title": "Logged Out",
            "URS_URL": "urs_url",
            "contentstring": "You are logged out."
        },
        {"Content-Type": "text/html", "asf-cookie": {}},
        200,
        "root.html"
    )


@mock.patch(f"{MODULE}.do_login", autospec=True)
def test_login(mock_do_login, mock_retrieve_secret, client):
    del mock_retrieve_secret

    mock_do_login.return_value = (301, {"foo": "bar"}, {"baz": "qux"})

    response = client.http.get("/login")

    assert response.body == b""
    assert response.status_code == 301
    assert response.headers == {
        "x-request-id": app.app.lambda_context.aws_request_id,
        "baz": "qux"
    }


@mock.patch(f"{MODULE}.do_login", autospec=True)
def test_login_error(
    mock_do_login,
    mock_retrieve_secret,
    mock_make_html_response,
    client
):
    del mock_retrieve_secret

    mock_do_login.side_effect = ClientError({}, "foo")

    response = client.http.get("/login")

    assert response.headers["x-request-id"] == app.app.lambda_context.aws_request_id
    mock_make_html_response.assert_called_once_with(
        {
            "contentstring": "Client Error occurred. ",
            "title": "Client Error",
            "requestid": app.app.lambda_context.aws_request_id
        },
        {},
        500,
        "error.html"
    )


def test_version(mock_retrieve_secret, monkeypatch, client):
    del mock_retrieve_secret

    response = client.http.get("/version")

    assert response.json_body == {"version_id": "<BUILD_ID>"}
    assert response.status_code == 200

    monkeypatch.setenv("BUMP", "bump_version")
    response = client.http.get("/version")

    assert response.json_body == {"version_id": "<BUILD_ID>", "last_flush": "bump_version"}
    assert response.status_code == 200


@mock.patch(f"{MODULE}.get_yaml_file", autospec=True)
@mock.patch(f"{MODULE}.b_map", None)
def test_locate(
    mock_get_yaml_file,
    mock_retrieve_secret,
    data_path,
    monkeypatch,
    client,
):
    del mock_retrieve_secret

    with open(data_path / "bucket_map_example.yaml") as f:
        mock_get_yaml_file.return_value = yaml.full_load(f)

    monkeypatch.setenv("BUCKETNAME_PREFIX", "")

    response = client.http.get("/locate?bucket_name=pa-dt1")
    assert response.status_code == 200
    assert response.json_body == ["DATA-TYPE-1/PLATFORM-A"]

    response = client.http.get("/locate?bucket_name=nonexistent")
    assert response.status_code == 404
    assert response.body == b"No route defined for nonexistent"


@mock.patch(f"{MODULE}.get_yaml_file", autospec=True)
@mock.patch(f"{MODULE}.b_map", None)
def test_locate_old_style_bucket_map(
    mock_get_yaml_file,
    mock_retrieve_secret,
    data_path,
    monkeypatch,
    client,
):
    del mock_retrieve_secret

    with open(data_path / "old_style_bucket_map_example.yaml") as f:
        mock_get_yaml_file.return_value = yaml.full_load(f)

    monkeypatch.setenv("BUCKETNAME_PREFIX", "")

    response = client.http.get("/locate?bucket_name=pa-dt1")
    assert response.status_code == 200
    assert response.json_body == ["DATA-TYPE-1/PLATFORM-A"]

    response = client.http.get("/locate?bucket_name=nonexistent")
    assert response.status_code == 404
    assert response.body == b"No route defined for nonexistent"


@mock.patch(f"{MODULE}.get_yaml_file", autospec=True)
@mock.patch(f"{MODULE}.b_map", None)
def test_locate_bucket_name_prefix(
    mock_get_yaml_file,
    mock_retrieve_secret,
    data_path,
    monkeypatch,
    client,
):
    del mock_retrieve_secret

    with open(data_path / "bucket_map_example.yaml") as f:
        mock_get_yaml_file.return_value = yaml.full_load(f)

    monkeypatch.setenv("BUCKETNAME_PREFIX", "bucket-prefix-")

    response = client.http.get("/locate?bucket_name=bucket-prefix-pa-dt1")
    assert response.status_code == 200
    assert response.json_body == ["DATA-TYPE-1/PLATFORM-A"]

    response = client.http.get("/locate?bucket_name=pa-dt1")
    assert response.status_code == 404
    assert response.body == b"No route defined for pa-dt1"

    response = client.http.get("/locate?bucket_name=nonexistent")
    assert response.status_code == 404
    assert response.body == b"No route defined for nonexistent"


@pytest.mark.parametrize("req", ("/locate", "/locate?foo=bar"))
@mock.patch(f"{MODULE}.b_map", None)
def test_locate_missing_bucket(mock_retrieve_secret, client, req):
    del mock_retrieve_secret

    response = client.http.get(req)
    assert response.body == b'Required "bucket_name" query paramater not specified'
    assert response.status_code == 400
    assert response.headers == {
        "x-request-id": app.app.lambda_context.aws_request_id,
        "Content-Type": "text/plain"
    }


def test_get_range_header_val(current_request):
    current_request.headers = {"Range": "v1"}
    assert app.get_range_header_val() == "v1"

    current_request.headers = {"range": "v2"}
    assert app.get_range_header_val() == "v2"

    current_request.headers = {"Range": "v1", "range": "v2"}
    assert app.get_range_header_val() == "v1"

    current_request.headers = {}
    assert app.get_range_header_val() is None


@mock.patch(f"{MODULE}.get_role_session", autospec=True)
def test_get_new_session_client(mock_get_role_session):
    client = mock_get_role_session().client()

    assert app.get_new_session_client("user_name") == client
    # Once in test setup and once during `get_new_session_client`
    assert mock_get_role_session.call_count == 2
    mock_get_role_session.assert_called_with(user_id="user_name")


@mock.patch(f"{MODULE}.get_new_session_client", autospec=True)
def test_get_bc_config_client_cached(mock_get_new_session_client):
    app.get_bc_config_client("user_name")
    mock_get_new_session_client.assert_called_once_with("user_name")
    app.get_bc_config_client("user_name")
    mock_get_new_session_client.assert_called_once_with("user_name")


@mock.patch(f"{MODULE}.JwtManager.get_profile_from_headers", autospec=True)
@mock.patch(f"{MODULE}.get_bc_config_client", autospec=True)
@mock.patch(f"{MODULE}.JWT_COOKIE_NAME", "asf-cookie")
def test_get_data_dl_s3_client(mock_get_bc_config_client, mock_get_profile, user_profile, current_request):
    mock_get_profile.return_value = user_profile
    user_profile.user_id = "username"

    app.get_data_dl_s3_client()
    mock_get_bc_config_client.assert_called_once_with("username")


@mock.patch(f"{MODULE}.get_data_dl_s3_client", autospec=True)
@mock.patch(f"{MODULE}.get_role_creds", autospec=True)
@mock.patch(f"{MODULE}.get_role_session", autospec=True)
@mock.patch(f"{MODULE}.get_presigned_url", autospec=True)
def test_try_download_head(
    mock_get_presigned_url,
    mock_get_role_session,
    mock_get_role_creds,
    mock_get_data_dl_s3_client,
    current_request,
    monkeypatch
):
    monkeypatch.setenv("CORS_ORIGIN", "example.com")
    current_request.headers = {"origin": "example.com"}
    mock_get_role_creds.return_value = (mock.Mock(), 1000)
    presigned_url = "somebucket.s3.us-west-2.amazonaws.com"
    mock_get_presigned_url.return_value = presigned_url

    response = app.try_download_head("bucket", "filename")

    assert response.body == ""
    assert response.status_code == 303
    assert response.headers == {
        "Location": presigned_url,
        "Access-Control-Allow-Origin": "example.com",
        "Access-Control-Allow-Credentials": "true"
    }
    mock_get_data_dl_s3_client.assert_called_once()
    mock_get_role_creds.assert_called_once()
    mock_get_role_session.assert_called_once()


@mock.patch(f"{MODULE}.get_data_dl_s3_client", autospec=True)
def test_try_download_head_error(
    mock_get_data_dl_s3_client,
    current_request,
    monkeypatch,
    mock_make_html_response
):
    monkeypatch.setenv("CORS_ORIGIN", "example.com")
    current_request.headers = {"origin": "example.com"}
    mock_get_data_dl_s3_client().get_object.side_effect = ClientError({}, "foo")

    app.try_download_head("bucket", "filename")

    mock_make_html_response.assert_called_once_with(
        {
            "contentstring": "File not found",
            "title": "File not found",
            "requestid": "request_1234"
        },
        {},
        404,
        "error.html"
    )


@mock.patch(f"{MODULE}.b_map", None)
def test_dynamic_url_options(current_request, monkeypatch):
    monkeypatch.setenv("CORS_ORIGIN", "example.com")
    current_request.headers = {
        "origin": "example.com",
        "access-control-request-method": "GET",
    }

    current_request.uri_params = {"proxy": "DATA-TYPE-1/PLATFORM-A/OBJECT_1"}

    # Can't use the chalice test client here as it doesn't seem to understand the `{proxy+}` route
    response = app.dynamic_url_options()

    assert response.body == ""
    assert response.status_code == 204
    assert response.headers == {
        "Access-Control-Allow-Origin": "example.com",
        "Access-Control-Allow-Credentials": "true",
        "Access-Control-Allow-Methods": "GET, HEAD, OPTIONS",
        "Access-Control-Allow-Headers": "Authorization, Origin, X-Requested-With",
    }


@mock.patch(f"{MODULE}.b_map", None)
def test_dynamic_url_options_error(current_request):
    current_request.uri_params = {"proxy": "DATA-TYPE-1/PLATFORM-A/OBJECT_1"}

    # Can't use the chalice test client here as it doesn't seem to understand the `{proxy+}` route
    response = app.dynamic_url_options()

    assert response.body == "Method Not Allowed"
    assert response.status_code == 405
    assert response.headers == {}


@mock.patch(f"{MODULE}.get_yaml_file", autospec=True)
@mock.patch(f"{MODULE}.try_download_head", autospec=True)
@mock.patch(f"{MODULE}.b_map", None)
def test_dynamic_url_head(
    mock_try_download_head,
    mock_get_yaml_file,
    data_path,
    current_request
):
    mock_try_download_head.return_value = chalice.Response(body="Mock response", headers={}, status_code=200)
    with open(data_path / "bucket_map_example.yaml") as f:
        mock_get_yaml_file.return_value = yaml.full_load(f)

    current_request.uri_params = {"proxy": "DATA-TYPE-1/PLATFORM-A/OBJECT_1"}

    # Can't use the chalice test client here as it doesn't seem to understand the `{proxy+}` route
    response = app.dynamic_url_head()

    mock_try_download_head.assert_called_once_with("gsfc-ngap-d-pa-dt1", "OBJECT_1")
    assert response.body == "Mock response"
    assert response.status_code == 200
    assert response.headers == {}


@mock.patch(f"{MODULE}.get_yaml_file", autospec=True)
@mock.patch(f"{MODULE}.b_map", None)
def test_dynamic_url_head_bad_bucket(
    mock_get_yaml_file,
    mock_make_html_response,
    data_path,
    current_request
):
    with open(data_path / "bucket_map_example.yaml") as f:
        mock_get_yaml_file.return_value = yaml.full_load(f)

    current_request.uri_params = {"proxy": "DATA-TYPE-1/NONEXISTENT/OBJECT_1"}

    # Can't use the chalice test client here as it doesn't seem to understand the `{proxy+}` route
    response = app.dynamic_url_head()

    mock_make_html_response.assert_called_once_with(
        {
            "contentstring": "Bucket not available",
            "title": "Bucket not available",
            "requestid": "request_1234"
        },
        {},
        404,
        "error.html"
    )
    assert response.body == "Mock response"
    assert response.status_code == 404
    assert response.headers == {"Content-Type": "text/html"}


@mock.patch(f"{MODULE}.get_yaml_file", autospec=True)
@mock.patch(f"{MODULE}.b_map", None)
def test_dynamic_url_head_missing_proxy(mock_get_yaml_file, current_request):
    mock_get_yaml_file.return_value = {}
    current_request.uri_params = {}

    # Can't use the chalice test client here as it doesn't seem to understand the `{proxy+}` route
    response = app.dynamic_url_head()

    assert response.body == "HEAD failed"
    assert response.status_code == 400


@mock.patch(f"{MODULE}.get_yaml_file", autospec=True)
@mock.patch(f"{MODULE}.get_api_request_uuid", autospec=True)
@mock.patch(f"{MODULE}.try_download_from_bucket", autospec=True)
@mock.patch(f"{MODULE}.JwtManager.get_profile_from_headers", autospec=True)
@mock.patch(f"{MODULE}.JWT_COOKIE_NAME", "asf-cookie")
@mock.patch(f"{MODULE}.b_map", None)
def test_dynamic_url(
    mock_get_profile,
    mock_try_download_from_bucket,
    mock_get_api_request_uuid,
    mock_get_yaml_file,
    data_path,
    user_profile,
    current_request
):
    MOCK_RESPONSE = mock.Mock()
    mock_try_download_from_bucket.return_value = MOCK_RESPONSE
    with open(data_path / "bucket_map_example.yaml") as f:
        mock_get_yaml_file.return_value = yaml.full_load(f)

    mock_get_profile.return_value = user_profile
    mock_get_api_request_uuid.return_value = None
    current_request.uri_params = {"proxy": "DATA-TYPE-1/PLATFORM-A/OBJECT_1"}

    # Can't use the chalice test client here as it doesn't seem to understand the `{proxy+}` route
    response = app.dynamic_url()

    mock_try_download_from_bucket.assert_called_once_with(
        "gsfc-ngap-d-pa-dt1",
        "OBJECT_1",
        user_profile,
        {},
        None
    )
    assert response is MOCK_RESPONSE


@mock.patch(f"{MODULE}.get_yaml_file", autospec=True)
@mock.patch(f"{MODULE}.get_api_request_uuid", autospec=True)
@mock.patch(f"{MODULE}.try_download_from_bucket", autospec=True)
@mock.patch(f"{MODULE}.JwtManager.get_profile_from_headers", autospec=True)
@mock.patch(f"{MODULE}.JWT_COOKIE_NAME", "asf-cookie")
@mock.patch(f"{MODULE}.b_map", None)
def test_dynamic_url_public_unauthenticated(
    mock_get_profile,
    mock_try_download_from_bucket,
    mock_get_api_request_uuid,
    mock_get_yaml_file,
    data_path,
    current_request
):
    MOCK_RESPONSE = mock.Mock()
    mock_try_download_from_bucket.return_value = MOCK_RESPONSE
    with open(data_path / "bucket_map_example.yaml") as f:
        mock_get_yaml_file.return_value = yaml.full_load(f)

    mock_get_profile.return_value = None
    mock_get_api_request_uuid.return_value = None
    current_request.uri_params = {"proxy": "BROWSE/PLATFORM-A/OBJECT_2"}

    # Can't use the chalice test client here as it doesn't seem to understand the `{proxy+}` route
    response = app.dynamic_url()

    mock_try_download_from_bucket.assert_called_once_with("gsfc-ngap-d-pa-bro", "OBJECT_2", None, {}, None)
    assert response is MOCK_RESPONSE


@mock.patch(f"{MODULE}.get_yaml_file", autospec=True)
@mock.patch(f"{MODULE}.get_api_request_uuid", autospec=True)
@mock.patch(f"{MODULE}.try_download_from_bucket", autospec=True)
@mock.patch(f"{MODULE}.JwtManager.get_profile_from_headers", autospec=True)
@mock.patch(f"{MODULE}.JWT_COOKIE_NAME", "asf-cookie")
@mock.patch(f"{MODULE}.b_map", None)
def test_dynamic_url_public_authenticated(
    mock_get_profile,
    mock_try_download_from_bucket,
    mock_get_api_request_uuid,
    mock_get_yaml_file,
    data_path,
    user_profile,
    current_request
):
    MOCK_RESPONSE = mock.Mock()
    mock_try_download_from_bucket.return_value = MOCK_RESPONSE
    with open(data_path / "bucket_map_example.yaml") as f:
        mock_get_yaml_file.return_value = yaml.full_load(f)

    mock_get_profile.return_value = user_profile
    mock_get_api_request_uuid.return_value = None
    current_request.uri_params = {"proxy": "BROWSE/PLATFORM-A/OBJECT_2"}

    # Can't use the chalice test client here as it doesn't seem to understand the `{proxy+}` route
    response = app.dynamic_url()

    mock_try_download_from_bucket.assert_called_once_with("gsfc-ngap-d-pa-bro", "OBJECT_2", user_profile, {}, None)
    assert response is MOCK_RESPONSE


@mock.patch(f"{MODULE}.get_yaml_file", autospec=True)
@mock.patch(f"{MODULE}.get_api_request_uuid", autospec=True)
@mock.patch(f"{MODULE}.try_download_from_bucket", autospec=True)
@mock.patch(f"{MODULE}.JwtManager.get_profile_from_headers", autospec=True)
@mock.patch(f"{MODULE}.JWT_COOKIE_NAME", "asf-cookie")
@mock.patch(f"{MODULE}.b_map", None)
def test_dynamic_url_public_custom_headers(
    mock_get_profile,
    mock_try_download_from_bucket,
    mock_get_api_request_uuid,
    mock_get_yaml_file,
    data_path,
    current_request
):
    MOCK_RESPONSE = mock.Mock()
    mock_try_download_from_bucket.return_value = MOCK_RESPONSE
    with open(data_path / "bucket_map_example.yaml") as f:
        mock_get_yaml_file.return_value = yaml.full_load(f)

    mock_get_profile.return_value = None
    mock_get_api_request_uuid.return_value = None
    current_request.uri_params = {"proxy": "HEADERS/BROWSE/OBJECT_1"}

    # Can't use the chalice test client here as it doesn't seem to understand the `{proxy+}` route
    response = app.dynamic_url()

    mock_try_download_from_bucket.assert_called_once_with(
        "gsfc-ngap-d-pa-bro",
        "OBJECT_1",
        None,
        {
            "custom-header-1": "custom-header-1-value",
            "custom-header-2": "custom-header-2-value"
        },
        None
    )
    assert response is MOCK_RESPONSE


@mock.patch(f"{MODULE}.get_yaml_file", autospec=True)
@mock.patch(f"{MODULE}.get_api_request_uuid", autospec=True)
@mock.patch(f"{MODULE}.try_download_from_bucket", autospec=True)
@mock.patch(f"{MODULE}.user_in_group", autospec=True)
@mock.patch(f"{MODULE}.JwtManager.get_profile_from_headers", autospec=True)
@mock.patch(f"{MODULE}.JwtManager.get_header_to_set_auth_cookie", autospec=True)
@mock.patch(f"{MODULE}.JWT_COOKIE_NAME", "asf-cookie")
@mock.patch(f"{MODULE}.b_map", None)
def test_dynamic_url_private(
    mock_get_header_to_set_auth_cookie,
    mock_get_profile,
    mock_user_in_group,
    mock_try_download_from_bucket,
    mock_get_api_request_uuid,
    mock_get_yaml_file,
    data_path,
    user_profile,
    current_request
):
    MOCK_RESPONSE = mock.Mock()
    mock_try_download_from_bucket.return_value = MOCK_RESPONSE
    mock_get_header_to_set_auth_cookie.return_value = {"SET-COOKIE": "cookie"}
    mock_user_in_group.return_value = (True, user_profile)
    with open(data_path / "bucket_map_example.yaml") as f:
        mock_get_yaml_file.return_value = yaml.full_load(f)

    mock_get_profile.return_value = user_profile
    mock_get_api_request_uuid.return_value = None
    current_request.uri_params = {"proxy": "PRIVATE/PLATFORM-A/OBJECT_2"}

    # Can't use the chalice test client here as it doesn't seem to understand the `{proxy+}` route
    response = app.dynamic_url()

    mock_try_download_from_bucket.assert_called_once_with(
        "gsfc-ngap-d-pa-priv",
        "OBJECT_2",
        user_profile,
        {"SET-COOKIE": "cookie"},
        None
    )
    assert response is MOCK_RESPONSE


@mock.patch(f"{MODULE}.get_yaml_file", autospec=True)
@mock.patch(f"{MODULE}.get_api_request_uuid", autospec=True)
@mock.patch(f"{MODULE}.try_download_from_bucket", autospec=True)
@mock.patch(f"{MODULE}.user_in_group", autospec=True)
@mock.patch(f"{MODULE}.JwtManager.get_profile_from_headers", autospec=True)
@mock.patch(f"{MODULE}.JwtManager.get_header_to_set_auth_cookie", autospec=True)
@mock.patch(f"{MODULE}.JWT_COOKIE_NAME", "asf-cookie")
@mock.patch(f"{MODULE}.b_map", None)
def test_dynamic_url_private_custom_headers(
    mock_get_header_to_set_auth_cookie,
    mock_get_profile,
    mock_user_in_group,
    mock_try_download_from_bucket,
    mock_get_api_request_uuid,
    mock_get_yaml_file,
    data_path,
    user_profile,
    current_request
):
    MOCK_RESPONSE = mock.Mock()
    mock_try_download_from_bucket.return_value = MOCK_RESPONSE

    mock_get_header_to_set_auth_cookie.return_value = {"SET-COOKIE": "cookie"}
    mock_user_in_group.return_value = (True, user_profile)
    with open(data_path / "bucket_map_example.yaml") as f:
        mock_get_yaml_file.return_value = yaml.full_load(f)

    mock_get_profile.return_value = user_profile
    mock_get_api_request_uuid.return_value = None
    current_request.uri_params = {"proxy": "HEADERS/PRIVATE/OBJECT_1"}

    # Can't use the chalice test client here as it doesn't seem to understand the `{proxy+}` route
    response = app.dynamic_url()

    mock_try_download_from_bucket.assert_called_once_with(
        "gsfc-ngap-d-pa-priv",
        "OBJECT_1",
        user_profile,
        {
            "custom-header-3": "custom-header-3-value",
            "custom-header-4": "custom-header-4-value",
            "SET-COOKIE": "cookie"
        },
        None
    )
    assert response is MOCK_RESPONSE


@mock.patch(f"{MODULE}.get_yaml_file", autospec=True)
@mock.patch(f"{MODULE}.get_api_request_uuid", autospec=True)
@mock.patch(f"{MODULE}.try_download_from_bucket", autospec=True)
@mock.patch(f"{MODULE}.JwtManager.get_profile_from_headers", autospec=True)
@mock.patch(f"{MODULE}.JWT_COOKIE_NAME", "asf-cookie")
@mock.patch(f"{MODULE}.b_map", None)
def test_dynamic_url_public_within_private(
    mock_get_profile_from_headers,
    mock_try_download_from_bucket,
    mock_get_api_request_uuid,
    mock_get_yaml_file,
    current_request
):
    # TODO(reweeden): Make an end-to-end version of this test as well
    MOCK_RESPONSE = mock.Mock()
    mock_try_download_from_bucket.return_value = MOCK_RESPONSE
    mock_get_yaml_file.return_value = {
        "MAP": {
            "FOO": "bucket"
        },
        "PUBLIC_BUCKETS": ["bucket/BROWSE"],
        "PRIVATE_BUCKETS": {
            "bucket": ["PERMISSION"]
        }
    }

    mock_get_profile_from_headers.return_value = None
    mock_get_api_request_uuid.return_value = None
    current_request.uri_params = {"proxy": "FOO/BROWSE/OBJECT_1"}

    # Can't use the chalice test client here as it doesn't seem to understand the `{proxy+}` route
    response = app.dynamic_url()

    mock_try_download_from_bucket.assert_called_once_with("gsfc-ngap-d-bucket", "BROWSE/OBJECT_1", None, {}, None)
    assert response is MOCK_RESPONSE


@mock.patch(f"{MODULE}.get_yaml_file", autospec=True)
def test_dynamic_url_bad_bucket(
    mock_get_yaml_file,
    mock_make_html_response,
    data_path,
    current_request
):
    with open(data_path / "bucket_map_example.yaml") as f:
        mock_get_yaml_file.return_value = yaml.full_load(f)

    current_request.uri_params = {"proxy": "DATA-TYPE-1/NONEXISTENT/OBJECT_1"}

    # Can't use the chalice test client here as it doesn't seem to understand the `{proxy+}` route
    response = app.dynamic_url()

    # TODO(reweeden): Why is the text different for get and head?
    mock_make_html_response.assert_called_once_with(
        {
            "contentstring": "File not found",
            "title": "File not found",
            "requestid": "request_1234"
        },
        {},
        404,
        "error.html"
    )
    assert response.body == "Mock response"
    assert response.status_code == 404
    assert response.headers == {"Content-Type": "text/html"}


@mock.patch(f"{MODULE}.get_yaml_file", autospec=True)
@mock.patch(f"{MODULE}.JwtManager.get_profile_from_headers", autospec=True)
@mock.patch(f"{MODULE}.JWT_COOKIE_NAME", "asf-cookie")
def test_dynamic_url_directory(
    mock_get_profile,
    mock_get_yaml_file,
    mock_make_html_response,
    data_path,
    user_profile,
    current_request
):
    with open(data_path / "bucket_map_example.yaml") as f:
        mock_get_yaml_file.return_value = yaml.full_load(f)

    mock_get_profile.return_value = user_profile
    current_request.uri_params = {"proxy": "DATA-TYPE-1/PLATFORM-A/"}

    # Can't use the chalice test client here as it doesn't seem to understand the `{proxy+}` route
    response = app.dynamic_url()

    mock_make_html_response.assert_called_once_with(
        {
            "contentstring": "Request does not appear to be valid.",
            "title": "Request Not Serviceable",
            "requestid": "request_1234"
        },
        {},
        404,
        "error.html"
    )
    assert response.body == "Mock response"
    assert response.status_code == 404
    assert response.headers == {"Content-Type": "text/html"}


@mock.patch(f"{MODULE}.get_yaml_file", autospec=True)
@mock.patch(f"{MODULE}.get_api_request_uuid", autospec=True)
@mock.patch(f"{MODULE}.try_download_from_bucket", autospec=True)
@mock.patch(f"{MODULE}.JwtManager.get_profile_from_headers", autospec=True)
@mock.patch(f"{MODULE}.RequestAuthorizer._handle_auth_bearer_header", autospec=True)
@mock.patch(f"{MODULE}.JwtManager.get_header_to_set_auth_cookie", autospec=True)
@mock.patch(f"{MODULE}.JWT_COOKIE_NAME", "asf-cookie")
@mock.patch(f"{MODULE}.b_map", None)
def test_dynamic_url_bearer_auth(
    mock_get_header_to_set_auth_cookie,
    mock_handle_auth_bearer_header,
    mock_get_profile,
    mock_try_download_from_bucket,
    mock_get_api_request_uuid,
    mock_get_yaml_file,
    data_path,
    user_profile,
    current_request
):
    mock_try_download_from_bucket.return_value = chalice.Response(body="Mock response", headers={}, status_code=200)
    mock_handle_auth_bearer_header.return_value = user_profile
    mock_get_header_to_set_auth_cookie.return_value = {"SET-COOKIE": "cookie"}
    with open(data_path / "bucket_map_example.yaml") as f:
        mock_get_yaml_file.return_value = yaml.full_load(f)

    mock_get_profile.return_value = None
    mock_get_api_request_uuid.return_value = None
    current_request.uri_params = {"proxy": "DATA-TYPE-1/PLATFORM-A/OBJECT_1"}
    current_request.headers = {"Authorization": "bearer b64token"}

    # Can't use the chalice test client here as it doesn't seem to understand the `{proxy+}` route
    response = app.dynamic_url()

    mock_try_download_from_bucket.assert_called_once_with(
        "gsfc-ngap-d-pa-dt1",
        "OBJECT_1",
        user_profile,
        {"SET-COOKIE": "cookie"},
        None
    )
    assert response.body == "Mock response"
    assert response.status_code == 200
    assert response.headers == {}


@mock.patch(f"{MODULE}.get_s3_credentials", autospec=True)
@mock.patch(f"{MODULE}.get_yaml_file", autospec=True)
@mock.patch(f"{MODULE}.JwtManager.get_profile_from_headers", autospec=True)
@mock.patch(f"{MODULE}.b_map", None)
def test_s3credentials(
    mock_get_profile,
    mock_get_yaml_file,
    mock_get_s3_credentials,
    mock_retrieve_secret,
    mock_get_urs_creds,
    data_path,
    user_profile,
    client
):
    del mock_retrieve_secret
    del mock_get_urs_creds

    mock_get_s3_credentials.return_value = {
        "AccessKeyId": "access_key",
        "SecretAccessKey": "secret_access_key",
        "SessionToken": "session_token",
        "Expiration": "expiration"
    }
    with open(data_path / "bucket_map_example.yaml") as f:
        mock_get_yaml_file.return_value = yaml.full_load(f)
    mock_get_profile.return_value = user_profile

    response = client.http.get("/s3credentials")

    assert response.json_body == {
        "accessKeyId": "access_key",
        "secretAccessKey": "secret_access_key",
        "sessionToken": "session_token",
        "expiration": "expiration"
    }
    assert response.status_code == 200


@mock.patch(f"{MODULE}.get_yaml_file", autospec=True)
@mock.patch(f"{MODULE}.RequestAuthorizer._handle_auth_bearer_header", autospec=True)
@mock.patch(f"{MODULE}.JwtManager.get_profile_from_headers", autospec=True)
@mock.patch(f"{MODULE}.do_auth_and_return", autospec=True)
@mock.patch(f"{MODULE}.b_map", None)
def test_s3credentials_unauthenticated(
    mock_do_auth_and_return,
    mock_get_profile,
    mock_handle_auth_bearer_header,
    mock_get_yaml_file,
    mock_retrieve_secret,
    data_path,
    client
):
    del mock_retrieve_secret

    mock_handle_auth_bearer_header.return_value = None
    with open(data_path / "bucket_map_example.yaml") as f:
        mock_get_yaml_file.return_value = yaml.full_load(f)
    mock_get_profile.return_value = None
    mock_response = chalice.Response(body="Mock response", headers={}, status_code=301)
    mock_do_auth_and_return.return_value = mock_response

    response = client.http.get("/s3credentials")

    assert response.body == b"Mock response"
    assert response.status_code == 301


@mock.patch(f"{MODULE}.get_yaml_file", autospec=True)
@mock.patch(f"{MODULE}.JwtManager.get_profile_from_headers", autospec=True)
@mock.patch(f"{MODULE}.b_map", None)
def test_s3credentials_no_permissions(
    mock_get_profile,
    mock_get_yaml_file,
    mock_retrieve_secret,
    mock_get_urs_creds,
    mock_make_html_response,
    user_profile,
    client
):
    del mock_retrieve_secret
    del mock_get_urs_creds

    mock_get_yaml_file.return_value = {}
    mock_get_profile.return_value = user_profile

    client.http.get("/s3credentials")

    mock_make_html_response.assert_called_once_with(
        {
            "contentstring": "You do not have permission to access any data.",
            "title": "Could not access data",
            "requestid": app.app.lambda_context.aws_request_id
        },
        {},
        403,
        "error.html"
    )


@mock.patch(f"{MODULE}.boto3")
def test_get_s3_credentials(mock_boto3, monkeypatch):
    monkeypatch.setenv("EGRESS_APP_DOWNLOAD_ROLE_INREGION_ARN", "aws:role:arn")
    client = mock_boto3.client("sts")

    app.get_s3_credentials("user", "role-session-name", policy={})

    client.assume_role.assert_called_once_with(
        RoleArn="aws:role:arn",
        RoleSessionName="role-session-name",
        ExternalId="user",
        DurationSeconds=3600,
        Policy="{}"
    )


def test_profile(mock_retrieve_secret, client):
    del mock_retrieve_secret

    response = client.http.get("/profile")

    assert response.body == b"Profile not available."
    assert response.status_code == 200
    assert response.headers["Content-Type"] == "text/plain"


def test_pubkey(mock_retrieve_secret, monkeypatch, client):
    mock_retrieve_secret.return_value = {
        "rsa_pub_key": base64.b64encode(b"pub-key").decode(),
        "rsa_priv_key": base64.b64encode(b"priv-key").decode()
    }
    monkeypatch.setattr(app.JWT_MANAGER, "algorithm", "algo")
    response = client.http.get("/pubkey")

    assert response.json_body == {"rsa_pub_key": "pub-key", "algorithm": "algo"}
    assert response.status_code == 200


def test_x_origin_request_id_forwarded(mock_retrieve_secret, client):
    del mock_retrieve_secret

    # Could be any endpoint, but profile is the simplest
    response = client.http.get("/profile", headers={"x-origin-request-id": "x_origin_request_1234"})

    assert response.headers["x-origin-request-id"] == "x_origin_request_1234"


def test_get_api_request_uuid():
    # Can't use the chalice test client here as it doesn't seem to understand the `{proxy+}` route
    response = app.get_api_request_uuid({"A-api-request-uuid": "test-uuid"})
    assert response == "test-uuid"
