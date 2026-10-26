import requests
from requests.auth import HTTPBasicAuth


def test_auth_process(urls, api_host, creds):
    url = urls.join(urls.METADATA_FILE)
    session = requests.session()
    # Disable automatic detection of .netrc.
    session.trust_env = False

    # Follow redirects to get the urthdata URL. We will get access denied because
    # we aren't passing our creds in yet.
    resp1 = session.get(url)
    assert resp1.status_code == 401

    url_earthdata = resp1.url
    urs_username, urs_password = creds.get(url_earthdata)
    resp2 = session.get(
        url_earthdata,
        auth=HTTPBasicAuth(urs_username, str(urs_password)),
    )

    assert resp2.status_code == 200
    cookiejar = session.cookies

    # Copy .asf.alaska.edu cookies to match API Address
    for z in cookiejar:
        if "asf.alaska.edu" in z.domain:
            cookiejar.set_cookie(
                requests.cookies.create_cookie(
                    domain=api_host,
                    name=z.name,
                    value=z.value,
                )
            )

    final_request = session.get(url, cookies=cookiejar)

    assert final_request.status_code == 200


def test_logout(urls, auth_cookies, url_earthdata):
    url = urls.join("logout")

    session = requests.Session()
    session.cookies.update(auth_cookies)

    r = session.get(url)
    assert "expired" in r.headers["Set-Cookie"]

    # After logout, the session can't access the file anymore
    r = session.get(urls.join(urls.METADATA_FILE), allow_redirects=False)
    assert r.status_code == 302
    assert r.is_redirect is True
    assert r.headers["Location"] == url_earthdata

    # A fresh session using the revoked creds also can't access the file anymore
    r = requests.get(
        urls.join(urls.METADATA_FILE),
        cookies=auth_cookies,
        allow_redirects=False,
    )
    assert r.status_code == 302
    assert r.is_redirect is True
    assert r.headers["Location"] == url_earthdata
