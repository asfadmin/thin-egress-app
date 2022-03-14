# Some common use cases that users might have for interacting with TEA data
# through GDAL. In particular using the vsicurl driver.
import hashlib
from http.cookiejar import MozillaCookieJar

import pytest

gdal = pytest.importorskip("osgeo.gdal")

GRANULE = "S1A_IW_SLC__1SVV_20150604T161908_20150604T161939_006226_008216_5A4E"
ZIP_FILE = f"{GRANULE}.zip"
SAFE_FILE = f"{GRANULE}.SAFE"
XML_FILE = "s1a-iw1-slc-vv-20150604t161908-20150604t161939-006226-008216-001.xml"
XML_SIZE = 995_130


@pytest.fixture(autouse=True)
def _config(tmp_path, auth_cookies):
    cookie_file_name = str(tmp_path / "cookies.txt")

    # Write the auth cookies to the file in a format that CURL can understand
    cookiejar = MozillaCookieJar(cookie_file_name)
    for cookie in auth_cookies:
        cookiejar.set_cookie(cookie)
    cookiejar.save(ignore_discard=True)

    gdal.UseExceptions()
    gdal.SetConfigOption("GDAL_HTTP_COOKIEFILE", cookie_file_name)
    gdal.SetConfigOption("GDAL_HTTP_COOKIEJAR", cookie_file_name)
    gdal.SetConfigOption("GDAL_HTTP_MAX_RETRY", "0")
    gdal.SetConfigOption("GDAL_DISABLE_READDIR_ON_OPEN", "TRUE")


def test_list_zip_contents(urls):
    url = urls.join("SA", "SLC", ZIP_FILE)
    res = gdal.ReadDir(f"/vsizip/vsicurl/{url}")

    assert res == [SAFE_FILE]


def test_download_file_contents(urls):
    url = urls.join("SA", "SLC", ZIP_FILE, SAFE_FILE, "annotation", XML_FILE)
    path = f"/vsizip/vsicurl/{url}"

    stats = gdal.VSIStatL(path)
    assert stats is not None
    assert stats.size == XML_SIZE

    vfid = gdal.VSIFOpenL(path, "rb")
    data = gdal.VSIFReadL(1, stats.size, vfid)
    gdal.VSIFCloseL(vfid)

    assert len(data) == XML_SIZE
    assert hashlib.md5(data).hexdigest() == "6f16f3342cec02a9f8ecc29fd4f51a86"
