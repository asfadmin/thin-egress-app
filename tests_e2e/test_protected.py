import base64
import json
import urllib.parse
from uuid import uuid1

import pytest
import requests

LOCATE_BUCKET = "rain-uw2-t-s1-ocn-1e29d408"


def test_urs_auth_redirect_for_auth_downloads(urls, auth_cookies, urs_username):
    url = urls.join(urls.METADATA_FILE)

    r = requests.get(url, cookies=auth_cookies, allow_redirects=False)

    assert r.status_code == 303
    assert r.is_redirect is True
    assert r.headers["Location"] is not None
    query_params = urllib.parse.parse_qs(
        urllib.parse.urlparse(r.headers["Location"]).query
    )
    assert query_params["A-userid"] == [urs_username]
    assert "oauth/authorize" not in r.headers["Location"]


def test_origin_request_header(urls, auth_cookies):
    url = urls.join(urls.METADATA_FILE)
    origin_request_value = str(uuid1())
    headers = {"x-origin-request-id": origin_request_value}

    r = requests.get(url, cookies=auth_cookies, headers=headers, allow_redirects=False)

    headers = dict(r.headers)
    assert headers.get("x-origin-request-id") == origin_request_value


@pytest.mark.parametrize("method", ("get", "head"))
def test_range_request_works(urls, auth_cookies, method):
    url = urls.join(urls.METADATA_FILE)
    headers = {"Range": "bytes=1035-1042"}

    r = requests.request(method, url, cookies=auth_cookies, headers=headers)

    assert r.status_code == 206
    assert r.headers["Content-Length"] == "8"
    if method == "get":
        assert len(r.text) == 8


@pytest.mark.parametrize("method", ("get", "head"))
def test_approved_user_can_access_private_data(urls, auth_cookies, method):
    url = urls.join("PRIVATE", "ACCESS", "testfile")

    r = requests.request(method, url, cookies=auth_cookies)

    assert r.status_code == 200


def test_approved_user_cant_access_private_data(urls, auth_cookies):
    url = urls.join("PRIVATE", "NOACCESS", "testfile")

    r = requests.get(url, cookies=auth_cookies)

    assert r.status_code == 403


def test_validating_objects_with_prefix(urls, auth_cookies):
    url = urls.join("SA", "BROWSE", "dir1", "dir2", "deepfile.txt")

    r = requests.get(url, cookies=auth_cookies)

    assert "file was successfully downloaded" in str(r.content)
    assert r.status_code == 200


def test_validate_custom_headers(urls, auth_cookies):
    url = urls.join(urls.METADATA_FILE_CH)

    r = requests.get(url, cookies=auth_cookies, allow_redirects=False)

    headers = dict(r.headers)
    assert headers.get("x-rainheader1") is not None


def test_validate_locate_handles_complex_configuration_key(api_url, auth_cookies):
    url = f"{api_url}/locate?bucket_name={LOCATE_BUCKET}"

    r = requests.get(url, cookies=auth_cookies)

    paths = sorted(json.loads(r.content))
    assert paths == ["SA/OCN", "SA/OCN_CH", "SB/OCN", "SB/OCN_CH"]


def find_bearer_token(auth_cookies):
    for cookie in auth_cookies:
        if cookie.name == "asf-urs":
            # Grab the JWT payload:
            cookie_b64 = cookie.value.split(".")[1]
            # Fix the padding:
            cookie_b64 += "=" * (4 - (len(cookie_b64) % 4))
            # Decode & Load...
            cookie_json = json.loads(base64.b64decode(cookie_b64))
            if "urs-access-token" in cookie_json:
                return cookie_json["urs-access-token"]
    return None


def test_validate_app_bearer_token(urls, auth_cookies):
    url = urls.join(urls.METADATA_FILE)
    token = find_bearer_token(auth_cookies)
    assert token is not None

    r = requests.get(url, headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200


def test_validate_app_bearer_token_private_file(urls, auth_cookies):
    url = urls.join("PRIVATE", "ACCESS", "testfile")
    token = find_bearer_token(auth_cookies)
    assert token is not None

    r = requests.get(url, headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200


def test_validate_user_bearer_token(urls, user_bearer_token):
    url = urls.join(urls.METADATA_FILE)

    r = requests.get(url, headers={"Authorization": f"Bearer {user_bearer_token}"})
    assert r.status_code == 200


def test_validate_user_bearer_token_private_file(urls, user_bearer_token):
    url = urls.join("PRIVATE", "ACCESS", "testfile")

    r = requests.get(url, headers={"Authorization": f"Bearer {user_bearer_token}"})
    assert r.status_code == 200
