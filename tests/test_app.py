import contextlib
import importlib
import io
from unittest import mock
from urllib.error import HTTPError

import chalice
import pytest
import yaml
from botocore.exceptions import ClientError
from chalice.test import Client

MODULE = "lambda.app"
# Can't import normally because 'lambda' is a reserved word
app = importlib.import_module(MODULE)


@pytest.fixture
def _clear_caches():
    app.get_bc_config_client.cache_clear()
    app.get_bucket_region_cache.clear()


@pytest.fixture(scope="module")
def client():
    return Client(app.app)


@pytest.fixture
def lambda_context():
    with mock.patch(f"{MODULE}.app.lambda_context") as ctx:
        yield ctx


@pytest.fixture
def current_request(lambda_context):
    lambda_context.aws_request_id = "request_1234"
    with mock.patch(f"{MODULE}.app.current_request") as req:
        yield req


@pytest.fixture
def mock_get_urs_creds():
    with mock.patch(f"{MODULE}.get_urs_creds", autospec=True) as m:
        m.return_value = {
            "UrsId": "stringofseeminglyrandomcharacters",
            "UrsAuth": "verymuchlongerstringofseeminglyrandomcharacters"
        }
        yield m


@pytest.fixture
def mock_make_html_response():
    with mock.patch(f"{MODULE}.make_html_response", autospec=True) as m:
        m.side_effect = lambda _1, headers, status_code, _4: chalice.Response(
            body="Mock response",
            headers=headers,
            status_code=status_code
        )
        yield m


@pytest.fixture
def mock_request():
    with mock.patch(f"{MODULE}.request", autospec=True) as m:
        yield m


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
def test_restore_bucket_vars(mock_get_yaml_file, resources):
    with resources.open("bucket_map_example.yaml") as f:
        buckets = yaml.full_load(f)

    mock_get_yaml_file.return_value = buckets
    app.b_map = None

    app.restore_bucket_vars()

    assert app.b_map == buckets


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


def test_send_cors_header(current_request, monkeypatch):
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


@mock.patch(f"{MODULE}.get_html_body", autospec=True)
def test_make_html_response(mock_get_html_body, monkeypatch):
    mock_get_html_body.return_value = "<html></html>"

    response = app.make_html_response({"foo": "bar"}, {"baz": "qux"})
    assert response.body == "<html></html>"
    assert response.status_code == 200
    assert response.headers == {"Content-Type": "text/html", "baz": "qux"}
    mock_get_html_body.assert_called_once_with({"STAGE": "DEV", "status_code": 200, "foo": "bar"}, "root.html")
    mock_get_html_body.reset_mock()

    monkeypatch.setenv("DOMAIN_NAME", "example.com")
    response = app.make_html_response({}, {}, 301, "redirect.html")
    assert response.body == "<html></html>"
    assert response.status_code == 301
    assert response.headers == {"Content-Type": "text/html"}
    mock_get_html_body.assert_called_once_with({"STAGE": None, "status_code": 301}, "redirect.html")


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
def test_try_download_from_bucket(
    mock_get_presigned_url,
    mock_get_role_session,
    mock_get_role_creds,
    mock_check_in_region_request,
    current_request,
    monkeypatch
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

    response = app.try_download_from_bucket("somebucket", "somefile", None, {})
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

    response = app.try_download_from_bucket("somebucket", "somefile", None, "not a dict")
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
    _clear_caches
):
    del current_request

    mock_get_role_creds.return_value = (mock.Mock(), 1000)
    mock_get_role_session().client.side_effect = ClientError({}, "bar")

    app.try_download_from_bucket("somebucket", "somefile", None, {})
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
    monkeypatch
):
    del current_request

    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    mock_get_role_creds.return_value = (mock.Mock(), 1000)
    mock_get_bc_config_client(None).head_object.side_effect = ClientError(
        {"ResponseMetadata": {"HTTPStatusCode": 404}},
        "bar"
    )

    app.try_download_from_bucket("somebucket", "somefile", None, {})
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
    monkeypatch
):
    del current_request

    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    mock_get_role_creds.return_value = (mock.Mock(), 1000)
    mock_get_bc_config_client(None).head_object.side_effect = ClientError(
        {"ResponseMetadata": {"HTTPStatusCode": 416}},
        "bar"
    )

    response = app.try_download_from_bucket("somebucket", "somefile", None, {})
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
def test_root(mock_get_urs_url, mock_make_html_response, client):
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
@mock.patch(f"{MODULE}.get_cookie_vars", autospec=True)
@mock.patch(f"{MODULE}.JWT_COOKIE_NAME", "asf-cookie")
def test_root_with_login(
    mock_get_cookie_vars,
    mock_get_urs_url,
    mock_make_html_response,
    monkeypatch,
    client
):
    monkeypatch.setenv("MATURITY", "DEV")
    mock_get_cookie_vars.return_value = {
        "asf-cookie": {
            "urs-user-id": "user_name"
        }
    }

    client.http.get("/")

    mock_get_urs_url.assert_not_called()
    mock_make_html_response.assert_called_once_with(
        {
            "title": "Welcome",
            "profile": {"urs-user-id": "user_name"}
        },
        {"Content-Type": "text/html"},
        200,
        "root.html"
    )

    # There is a profile but no user id
    mock_make_html_response.reset_mock()
    mock_get_cookie_vars.return_value = {"asf-cookie": {"foo": "bar"}}
    monkeypatch.setenv("MATURITY", "TEST")

    client.http.get("/")

    mock_get_urs_url.assert_not_called()
    mock_make_html_response.assert_called_once_with(
        {"title": "Welcome"},
        {"Content-Type": "text/html"},
        200,
        "root.html"
    )

    # There is no profile
    mock_make_html_response.reset_mock()
    mock_get_cookie_vars.return_value = {"foo": "bar"}
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
@mock.patch(f"{MODULE}.get_cookie_vars", autospec=True)
@mock.patch(f"{MODULE}.make_set_cookie_headers_jwt", autospec=True)
@mock.patch(f"{MODULE}.JWT_COOKIE_NAME", "asf-cookie")
def test_logout(
    mock_make_set_cookie_headers_jwt,
    mock_get_cookie_vars,
    mock_get_urs_url,
    mock_make_html_response,
    client
):
    mock_get_urs_url.return_value = "urs_url"
    mock_make_set_cookie_headers_jwt.return_value = {}
    mock_get_cookie_vars.return_value = {"asf-cookie": {}}

    client.http.get("/logout")

    mock_make_html_response.assert_called_once_with(
        {
            "title": "Logged Out",
            "URS_URL": "urs_url",
            "contentstring": "You are logged out."
        },
        {"Content-Type": "text/html"},
        200,
        "root.html"
    )


@mock.patch(f"{MODULE}.do_login", autospec=True)
def test_login(mock_do_login, client):
    mock_do_login.return_value = (301, {"foo": "bar"}, {"baz": "qux"})

    response = client.http.get("/login")

    assert response.body == b""
    assert response.status_code == 301
    assert response.headers == {
        "x-request-id": app.app.lambda_context.aws_request_id,
        "baz": "qux"
    }


@mock.patch(f"{MODULE}.do_login", autospec=True)
def test_login_error(mock_do_login, mock_make_html_response, client):
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


def test_version(monkeypatch, client):
    response = client.http.get("/version")

    assert response.json_body == {"version_id": "<BUILD_ID>"}
    assert response.status_code == 200

    monkeypatch.setenv("BUMP", "bump_version")
    response = client.http.get("/version")

    assert response.json_body == {"version_id": "<BUILD_ID>", "last_flush": "bump_version"}
    assert response.status_code == 200


@mock.patch(f"{MODULE}.get_yaml_file", autospec=True)
def test_locate(mock_get_yaml_file, resources, client):
    with resources.open("bucket_map_example.yaml") as f:
        mock_get_yaml_file.return_value = yaml.full_load(f)

    response = client.http.get("/locate?bucket_name=pa-dt1")
    assert response.json_body == ["DATA-TYPE-1/PLATFORM-A"]
    assert response.status_code == 200

    response = client.http.get("/locate?bucket_name=nonexistent")
    assert response.body == b"No route defined for nonexistent"
    assert response.status_code == 404


def test_locate_missing_bucket(client):
    for req in ("/locate", "/locate?foo=bar"):
        response = client.http.get(req)
        assert response.body == b'Required "bucket_name" query paramater not specified'
        assert response.status_code == 400
        assert response.headers == {
            "x-request-id": app.app.lambda_context.aws_request_id,
            "Content-Type": "text/plain"
        }


def test_collapse_bucket_configuration():
    bucket_map = {
        "foo": "bar",
        "key1": {
            "key2": {
                "bucket": "bucket1"
            }
        },
        "bucket": {
            "bucket": "bucket2"
        },
        "key3": {
            "bucket": {
                "bucket": {
                    "bucket": "bucket3"
                }
            }
        }
    }
    app.collapse_bucket_configuration(bucket_map)

    assert bucket_map == {
        "foo": "bar",
        "key1": {
            "key2": "bucket1"
        },
        "bucket": "bucket2",
        "key3": {
            "bucket": {
                "bucket": "bucket3"
            }
        }
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


@mock.patch(f"{MODULE}.get_cookie_vars", autospec=True)
@mock.patch(f"{MODULE}.get_bc_config_client", autospec=True)
@mock.patch(f"{MODULE}.JWT_COOKIE_NAME", "asf-cookie")
def test_get_data_dl_s3_client(mock_get_bc_config_client, mock_get_cookie_vars):
    mock_get_cookie_vars.return_value = {
        "asf-cookie": {
            "urs-user-id": "user_name"
        }
    }

    app.get_data_dl_s3_client()
    mock_get_bc_config_client.assert_called_once_with("user_name")


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


@mock.patch(f"{MODULE}.get_yaml_file", autospec=True)
@mock.patch(f"{MODULE}.try_download_head", autospec=True)
def test_dynamic_url_head(mock_try_download_head, mock_get_yaml_file, resources, current_request):
    mock_try_download_head.return_value = chalice.Response(body="Mock response", headers={}, status_code=200)
    with resources.open("bucket_map_example.yaml") as f:
        mock_get_yaml_file.return_value = yaml.full_load(f)

    current_request.uri_params = {"proxy": "DATA-TYPE-1/PLATFORM-A/OBJECT_1"}

    # Can't use the chalice test client here as it doesn't seem to understand the `{proxy+}` route
    response = app.dynamic_url_head()

    mock_try_download_head.assert_called_once_with("gsfc-ngap-d-pa-dt1", "OBJECT_1")
    assert response.body == "Mock response"
    assert response.status_code == 200
    assert response.headers == {}


@mock.patch(f"{MODULE}.get_yaml_file", autospec=True)
def test_dynamic_url_head_bad_bucket(mock_get_yaml_file, mock_make_html_response, resources, current_request):
    with resources.open("bucket_map_example.yaml") as f:
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
    assert response.headers == {}


@mock.patch(f"{MODULE}.get_yaml_file", autospec=True)
def test_dynamic_url_head_missing_proxy(mock_get_yaml_file, current_request):
    mock_get_yaml_file.return_value = {}
    current_request.uri_params = {}

    # Can't use the chalice test client here as it doesn't seem to understand the `{proxy+}` route
    response = app.dynamic_url_head()

    assert response.body == "HEAD failed"
    assert response.status_code == 400


@mock.patch(f"{MODULE}.get_user_from_token", autospec=True)
@mock.patch(f"{MODULE}.get_new_token_and_profile", autospec=True)
def test_handle_auth_bearer_header(mock_get_new_token_and_profile, mock_get_user_from_token, current_request):
    current_request.headers = {"x-origin-request-id": "origin_request_id"}
    mock_user_profile = mock.Mock()
    mock_get_new_token_and_profile.return_value = mock_user_profile
    mock_get_user_from_token.return_value = "user_name"

    assert app.handle_auth_bearer_header(mock.Mock()) == ("user_profile", mock_user_profile)
    mock_get_new_token_and_profile.assert_called_once_with(
        "user_name",
        True,
        aux_headers={
            "x-request-id": "request_1234",
            "x-origin-request-id": "origin_request_id"
        }
    )


@mock.patch(f"{MODULE}.get_user_from_token", autospec=True)
def test_handle_auth_bearer_header_eula_error(mock_get_user_from_token, current_request):
    current_request.headers = {"x-origin-request-id": "origin_request_id"}
    mock_get_user_from_token.side_effect = app.EulaException({})

    action, response = app.handle_auth_bearer_header(mock.Mock())
    assert action == "return"
    assert response.status_code == 403
    assert response.headers == {}


@mock.patch(f"{MODULE}.get_user_from_token", autospec=True)
def test_handle_auth_bearer_header_eula_error_browser(
    mock_get_user_from_token,
    mock_make_html_response,
    current_request
):
    current_request.headers = {"user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
    mock_get_user_from_token.side_effect = app.EulaException({
        "status_code": 403,
        "error_description": "EULA Acceptance Failure",
        "resolution_url": "http://resolution_url"
    })

    action, response = app.handle_auth_bearer_header(mock.Mock())
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
    assert action == "return"
    assert response.status_code == 403
    assert response.headers == {}


@mock.patch(f"{MODULE}.get_user_from_token", autospec=True)
@mock.patch(f"{MODULE}.get_new_token_and_profile", autospec=True)
@mock.patch(f"{MODULE}.do_auth_and_return", autospec=True)
def test_handle_auth_bearer_header_no_profile(
    mock_do_auth_and_return,
    mock_get_new_token_and_profile,
    mock_get_user_from_token,
    current_request
):
    current_request.headers = {"x-origin-request-id": "origin_request_id"}
    mock_response = mock.Mock()
    mock_do_auth_and_return.return_value = mock_response
    mock_get_new_token_and_profile.return_value = False
    mock_get_user_from_token.return_value = "user_name"

    assert app.handle_auth_bearer_header(mock.Mock()) == ("return", mock_response)
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
def test_handle_auth_bearer_header_no_user_id(
    mock_do_auth_and_return,
    mock_get_user_from_token,
    current_request
):
    current_request.headers = {"x-origin-request-id": "origin_request_id"}
    mock_response = mock.Mock()
    mock_do_auth_and_return.return_value = mock_response
    mock_get_user_from_token.return_value = None

    assert app.handle_auth_bearer_header(mock.Mock()) == ("return", mock_response)
    mock_do_auth_and_return.assert_called_once_with(current_request.context)


@mock.patch(f"{MODULE}.get_yaml_file", autospec=True)
@mock.patch(f"{MODULE}.try_download_from_bucket", autospec=True)
@mock.patch(f"{MODULE}.get_cookie_vars", autospec=True)
@mock.patch(f"{MODULE}.JWT_COOKIE_NAME", "asf-cookie")
def test_dynamic_url(
    mock_get_cookie_vars,
    mock_try_download_from_bucket,
    mock_get_yaml_file,
    resources,
    current_request
):
    mock_try_download_from_bucket.return_value = chalice.Response(body="Mock response", headers={}, status_code=200)
    with resources.open("bucket_map_example.yaml") as f:
        mock_get_yaml_file.return_value = yaml.full_load(f)

    mock_get_cookie_vars.return_value = {
        "asf-cookie": {
            "urs-user-id": "user_name"
        }
    }
    current_request.uri_params = {"proxy": "DATA-TYPE-1/PLATFORM-A/OBJECT_1"}

    # Can't use the chalice test client here as it doesn't seem to understand the `{proxy+}` route
    response = app.dynamic_url()

    mock_try_download_from_bucket.assert_called_once_with(
        "gsfc-ngap-d-pa-dt1",
        "OBJECT_1",
        {"urs-user-id": "user_name"},
        {}
    )
    assert response.body == "Mock response"
    assert response.status_code == 200
    assert response.headers == {}


@mock.patch(f"{MODULE}.get_yaml_file", autospec=True)
@mock.patch(f"{MODULE}.try_download_from_bucket", autospec=True)
@mock.patch(f"{MODULE}.get_cookie_vars", autospec=True)
@mock.patch(f"{MODULE}.JWT_COOKIE_NAME", "asf-cookie")
def test_dynamic_url_public(
    mock_get_cookie_vars,
    mock_try_download_from_bucket,
    mock_get_yaml_file,
    resources,
    current_request
):
    mock_try_download_from_bucket.return_value = chalice.Response(body="Mock response", headers={}, status_code=200)
    with resources.open("bucket_map_example.yaml") as f:
        mock_get_yaml_file.return_value = yaml.full_load(f)

    mock_get_cookie_vars.return_value = {}
    current_request.uri_params = {"proxy": "BROWSE/PLATFORM-A/OBJECT_2"}

    # Can't use the chalice test client here as it doesn't seem to understand the `{proxy+}` route
    response = app.dynamic_url()

    mock_try_download_from_bucket.assert_called_once_with("gsfc-ngap-d-pa-bro", "OBJECT_2", None, {})
    assert response.body == "Mock response"
    assert response.status_code == 200
    assert response.headers == {}


@mock.patch(f"{MODULE}.get_yaml_file", autospec=True)
@mock.patch(f"{MODULE}.try_download_from_bucket", autospec=True)
@mock.patch(f"{MODULE}.user_in_group", autospec=True)
@mock.patch(f"{MODULE}.get_cookie_vars", autospec=True)
@mock.patch(f"{MODULE}.make_set_cookie_headers_jwt", autospec=True)
@mock.patch(f"{MODULE}.JWT_COOKIE_NAME", "asf-cookie")
def test_dynamic_url_private(
    mock_make_set_cookie_headers_jwt,
    mock_get_cookie_vars,
    mock_user_in_group,
    mock_try_download_from_bucket,
    mock_get_yaml_file,
    resources,
    current_request
):
    mock_try_download_from_bucket.return_value = chalice.Response(body="Mock response", headers={}, status_code=200)
    user_profile = {
        "urs-user-id": "user_name",
        "urs-access-token": "access_token",
        "first_name": "First",
        "last_name": "Last",
        "email_address": "user@example.com",
        "user_groups": []
    }
    mock_make_set_cookie_headers_jwt.return_value = {"SET-COOKIE": "cookie"}
    mock_user_in_group.return_value = (True, user_profile)
    with resources.open("bucket_map_example.yaml") as f:
        mock_get_yaml_file.return_value = yaml.full_load(f)

    mock_get_cookie_vars.return_value = {"asf-cookie": user_profile}
    current_request.uri_params = {"proxy": "PRIVATE/PLATFORM-A/OBJECT_2"}

    # Can't use the chalice test client here as it doesn't seem to understand the `{proxy+}` route
    response = app.dynamic_url()

    mock_try_download_from_bucket.assert_called_once_with(
        "gsfc-ngap-d-pa-priv",
        "OBJECT_2",
        user_profile,
        {"SET-COOKIE": "cookie"}
    )
    assert response.body == "Mock response"
    assert response.status_code == 200
    assert response.headers == {}


@mock.patch(f"{MODULE}.get_yaml_file", autospec=True)
@mock.patch(f"{MODULE}.get_cookie_vars", autospec=True)
@mock.patch(f"{MODULE}.JWT_COOKIE_NAME", "asf-cookie")
def test_dynamic_url_directory(
    mock_get_cookie_vars,
    mock_get_yaml_file,
    mock_make_html_response,
    resources,
    current_request
):
    with resources.open("bucket_map_example.yaml") as f:
        mock_get_yaml_file.return_value = yaml.full_load(f)

    mock_get_cookie_vars.return_value = {
        "asf-cookie": {
            "urs-user-id": "user_name"
        }
    }
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
    assert response.headers == {}


@mock.patch(f"{MODULE}.get_yaml_file", autospec=True)
@mock.patch(f"{MODULE}.try_download_from_bucket", autospec=True)
@mock.patch(f"{MODULE}.get_cookie_vars", autospec=True)
@mock.patch(f"{MODULE}.handle_auth_bearer_header", autospec=True)
@mock.patch(f"{MODULE}.make_set_cookie_headers_jwt", autospec=True)
@mock.patch(f"{MODULE}.JWT_COOKIE_NAME", "asf-cookie")
def test_dynamic_url_bearer_auth(
    mock_make_set_cookie_headers_jwt,
    mock_handle_auth_bearer_header,
    mock_get_cookie_vars,
    mock_try_download_from_bucket,
    mock_get_yaml_file,
    resources,
    current_request
):
    mock_try_download_from_bucket.return_value = chalice.Response(body="Mock response", headers={}, status_code=200)
    mock_handle_auth_bearer_header.return_value = (
        "user_profile",
        {
            "uid": "user_name",
            "first_name": "First",
            "last_name": "Last",
            "email_address": "user@example.com",
            "user_groups": []
        }
    )
    mock_make_set_cookie_headers_jwt.return_value = {"SET-COOKIE": "cookie"}
    with resources.open("bucket_map_example.yaml") as f:
        mock_get_yaml_file.return_value = yaml.full_load(f)

    mock_get_cookie_vars.return_value = {}
    current_request.uri_params = {"proxy": "DATA-TYPE-1/PLATFORM-A/OBJECT_1"}
    current_request.headers = {"Authorization": "bearer b64token"}

    # Can't use the chalice test client here as it doesn't seem to understand the `{proxy+}` route
    response = app.dynamic_url()

    mock_try_download_from_bucket.assert_called_once_with(
        "gsfc-ngap-d-pa-dt1",
        "OBJECT_1",
        {
            "uid": "user_name",
            "first_name": "First",
            "last_name": "Last",
            "email_address": "user@example.com",
            "user_groups": []
        },
        {"SET-COOKIE": "cookie"}
    )
    assert response.body == "Mock response"
    assert response.status_code == 200
    assert response.headers == {}


def test_profile(client):
    response = client.http.get("/profile")

    assert response.body == b"Profile not available."
    assert response.status_code == 200


@mock.patch(f"{MODULE}.get_jwt_keys", autospec=True)
@mock.patch(f"{MODULE}.JWT_ALGO", "THE_ALGO")
def test_pubkey(get_keys_mock, client):
    get_keys_mock.return_value = {"rsa_pub_key": b"THE KEY"}

    response = client.http.get("/pubkey")

    assert response.json_body == {"rsa_pub_key": "THE KEY", "algorithm": "THE_ALGO"}
    assert response.status_code == 200


def test_x_origin_request_id_forwarded(client):
    # Could be any endpoint, but profile is the simplest
    response = client.http.get("/profile", headers={"x-origin-request-id": "x_origin_request_1234"})

    assert response.headers["x-origin-request-id"] == "x_origin_request_1234"
