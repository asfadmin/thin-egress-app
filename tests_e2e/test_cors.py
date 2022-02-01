import requests


def test_cors(urls, auth_cookies):
    origin_host = "https://something.asf.alaska.edu"

    url = urls.join(urls.METADATA_FILE_CH)
    origin_headers = {"origin": origin_host}

    r = requests.get(url, cookies=auth_cookies, headers=origin_headers, allow_redirects=False)
    headers = dict(r.headers)

    assert headers.get("Access-Control-Allow-Origin") == origin_host
    assert headers.get("Access-Control-Allow-Credentials") == "true"

    headers = {"origin": "null"}
    r = requests.get(url, cookies=auth_cookies, headers=headers, allow_redirects=False)
    headers = dict(r.headers)

    assert headers.get("Access-Control-Allow-Origin") == "null"
