# Check that public files are returned without auth
import requests

BROWSE_FILE = "SA/BROWSE/S1A_EW_GRDM_1SDH_20190206T190846_20190206T190951_025813_02DF0B_781A.jpg"
OBJ_PREFIX_FILE = "SA/METADATA_GRD_HS_CH/browse/ALAV2A104483200-OORIRFU_000.png"


def test_public_images(urls):
    url = urls.join(BROWSE_FILE)
    r = requests.get(url)

    assert r.status_code == 200
    assert r.headers["Content-Type"] == "image/jpeg"


def test_check_public_obj_prefix(urls):
    url = urls.join(OBJ_PREFIX_FILE)
    r = requests.get(url)

    assert r.status_code == 200


def test_404_on_bad_request(urls):
    url = urls.join("bad", "url.ext")
    r = requests.get(url)

    assert r.status_code == 404


def test_bad_cookie_value_cause_URS_redirect(urls):
    url = urls.join(urls.METADATA_FILE)
    cookies = {
        "urs_user_id": "badusername",
        "urs_access_token": "blah"
    }

    r = requests.get(url, cookies=cookies, allow_redirects=False)

    assert r.is_redirect is True
    assert r.headers["Location"] is not None
    assert "oauth/authorize" in r.headers["Location"]
