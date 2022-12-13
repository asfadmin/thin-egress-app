import requests


def test_unauthenticated_user_gets_error(urls):
    url = urls.join("s3credentials")

    r = requests.get(url)

    assert r.status_code == 401


def test_authenticated_user_can_get_creds(urls, auth_cookies):
    url = urls.join("s3credentials")

    r = requests.get(url, cookies=auth_cookies)
    data = r.json()

    assert r.status_code == 200
    assert list(data.keys()) == [
        "accessKeyId",
        "secretAccessKey",
        "sessionToken",
        "expiration"
    ]
