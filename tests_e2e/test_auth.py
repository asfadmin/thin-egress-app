import requests
from requests.auth import HTTPBasicAuth


def test_auth_process(urls, api_host, urs_username, urs_password):
    url = urls.join(urls.METADATA_FILE)
    session = requests.session()

    # Follow redirects to get the urthdata URL. We will get access denied because
    # we aren't passing our creds in yet.
    resp1 = session.get(url)
    assert resp1.status_code == 401

    url_earthdata = resp1.url
    resp2 = session.get(url_earthdata, auth=HTTPBasicAuth(urs_username, str(urs_password)))

    assert resp2.status_code == 200
    cookiejar = session.cookies

    # Copy .asf.alaska.edu cookies to match API Address
    for z in cookiejar:
        if "asf.alaska.edu" in z.domain:
            cookiejar.set_cookie(requests.cookies.create_cookie(
                domain=api_host,
                name=z.name,
                value=z.value
            ))

    final_request = session.get(url, cookies=cookiejar)

    assert final_request.status_code == 200
