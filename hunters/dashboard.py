from io import BytesIO
from logging import debug, warning

from PIL import Image
from requests import get
from selenium import webdriver
from selenium.webdriver.support import expected_conditions
from selenium.webdriver.support.ui import WebDriverWait

from hunters.hunter import Hunter

DASHBOARD_PATHS = [
    "/ui",
    "/api/v1/namespaces/kube-system/services/kubernetes-dashboard/proxy"
]

API = {
    "overview": "/api/v1/overview/default?itemsPerPage=100",
    "nodes": "/api/v1/node?itemsPerPage=100"
}

XPATH = {
    "login_skip": "/html/body/kd-login/form/kd-content-card/div/div/div/kd-content/button[2]"
}


def test_url(url):
    r = get(url)
    if r.status_code == 200:
        return r.url


class Dashboard(Hunter):
    def __init__(self, host):
        self.host = host
        if "://" not in host:
            self.host_url = "http://{}".format(host)
        else:
            self.host_url = host
        self._is_auth_required = None
        self._base_path = None

    def format_url(self, path):
        return self.base_path + path

    def list_nodes(self):
        return [str(n["objectMeta"]["name"]) for n in get(self.format_url(API["nodes"])).json()["nodes"]]

    @property
    def base_path(self):
        if self._base_path:
            return self._base_path
        for path in DASHBOARD_PATHS:
            path = test_url(self.host_url + path)
            if path:
                self._base_path = path
                return path
        raise Exception("User interface URL path was not found")

    @property
    def is_auth_required(self):
        if not self._is_auth_required:
            overview = get(self.format_url(API["overview"])).json()
            if "errors" in overview and overview["errors"]:
                self._is_auth_required = any([e["ErrStatus"]["code"] == 403 for e in overview["errors"]])
            else:
                self._is_auth_required = False
        return self._is_auth_required

    def take_screenshot(self):
        driver = webdriver.Chrome()
        driver.fullscreen_window()
        waiter = WebDriverWait(driver, 5)

        driver.get(self.base_path)
        waiter.until(lambda d: "Overview" in d.title or "Sign" in d.title)

        skip_buttons = driver.find_elements_by_xpath(XPATH["login_skip"])
        if skip_buttons:
            skip_buttons[0].click()
            waiter.until(expected_conditions.title_contains("Overview"))

        result = driver.get_screenshot_as_png()
        driver.quit()

        return result

    def hunt(self, *args, **kwargs):
        debug("Hunting dashboard at {}".format(self.host))

        debug("Checking authentication...")

        if self.is_auth_required:
            warning("Authentication is required")
            return

        debug("Authentication is not required")
        debug("Listing nodes on the cluster...")
        debug("Nodes: {}".format(self.list_nodes()))

        debug("Taking a screenshot...")
        Image.open(BytesIO(self.take_screenshot())).show()
