import requests


def test_cors(urls, auth_cookies):
    origin_host = "https://something.asf.alaska.edu"

    url = urls.join(urls.METADATA_FILE_CH)
    request_headers = {"origin": origin_host}

    r = requests.get(
        url,
        cookies=auth_cookies,
        headers=request_headers,
        allow_redirects=False,
    )
    headers = dict(r.headers)

    assert headers.get("Access-Control-Allow-Origin") == origin_host
    assert headers.get("Access-Control-Allow-Credentials") == "true"


def test_cors_origin_null(urls, auth_cookies):
    url = urls.join(urls.METADATA_FILE_CH)
    request_headers = {"origin": "null"}
    r = requests.get(
        url,
        cookies=auth_cookies,
        headers=request_headers,
        allow_redirects=False,
    )
    headers = dict(r.headers)

    assert headers.get("Access-Control-Allow-Origin") == "null"


def test_cors_preflight_options(urls, auth_cookies):
    origin_host = "https://something.asf.alaska.edu"

    url = urls.join(urls.METADATA_FILE_CH)
    request_headers = {
        "Origin": origin_host,
        "Access-Control-Request-Method": "GET"
    }

    r = requests.options(
        url,
        cookies=auth_cookies,
        headers=request_headers,
        allow_redirects=False,
    )
    headers = dict(r.headers)

    assert r.status_code == 204
    assert headers.get("Access-Control-Allow-Origin") == origin_host
    assert "GET" in headers.get("Access-Control-Allow-Methods")


def test_cors_preflight_options_origin_null(urls, auth_cookies):
    url = urls.join(urls.METADATA_FILE_CH)
    request_headers = {
        "Origin": "null",
        "Access-Control-Request-Method": "GET"
    }

    r = requests.options(
        url,
        cookies=auth_cookies,
        headers=request_headers,
        allow_redirects=False,
    )
    headers = dict(r.headers)

    assert r.status_code == 204
    assert headers.get("Access-Control-Allow-Origin") == "null"
    assert "GET" in headers.get("Access-Control-Allow-Methods")
