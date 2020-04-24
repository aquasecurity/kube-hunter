import requests
import requests_mock
import urllib.parse
import uuid

from kube_hunter.core.events import handler
from kube_hunter.modules.hunting.kubelet import AnonymousAuthEnabled, FootholdViaSecureKubeletPort, \
    ExposedExistingPrivilegedContainersViaSecureKubeletPort, MaliciousIntentViaSecureKubeletPort

counter = 0
pod_list_with_privileged_container = """{
  "kind": "PodList",
  "apiVersion": "v1",
  "metadata": {},
  "items": [
    {
      "metadata": {
        "name": "kube-hunter-privileged-deployment-86dc79f945-sjjps",
        "namespace": "kube-hunter-privileged"
      },
      "spec": {
        "containers": [
          {
            "name": "ubuntu",
            "securityContext": {
              {security_context_definition_to_test}
            }
          }
        ]
      }
    }
  ]
}
"""
service_account_token = "eyJhbGciOiJSUzI1NiIsImtpZCI6IlR0YmxoMXh..."
ca = """-----BEGIN CERTIFICATE-----
MIIC5zCCAc+gAwIBAgIBATANBgkqhkiG9w0BAQsFADAVMRMwEQYDVQQDEwptaW5p
...
-----END CERTIFICATE-----"""
env = """PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
HOSTNAME=kube-hunter-privileged-deployment-86dc79f945-sjjps
KUBERNETES_SERVICE_PORT=443
KUBERNETES_SERVICE_PORT_HTTPS=443
KUBERNETES_PORT=tcp://10.96.0.1:443
KUBERNETES_PORT_443_TCP=tcp://10.96.0.1:443
KUBERNETES_PORT_443_TCP_PROTO=tcp
KUBERNETES_PORT_443_TCP_PORT=443
KUBERNETES_PORT_443_TCP_ADDR=10.96.0.1
KUBERNETES_SERVICE_HOST=10.96.0.1
HOME=/root"""
exposed_privileged_containers = [
    {"certificate_authority": ca, "container_name": "ubuntu", "environment_variables": env,
     "pod_id": "kube-hunter-privileged-deployment-86dc79f945-sjjps", "pod_namespace": "kube-hunter-privileged",
     "service_account_token": service_account_token}
]
cat_proc_cmdline = "BOOT_IMAGE=/boot/bzImage root=LABEL=Mock loglevel=3 console=ttyS0"


def test_get_request_valid_url():
    anonymous_auth_enabled_event = AnonymousAuthEnabled()
    anonymous_auth_enabled_event.host = "localhost"

    with requests_mock.Mocker() as mocker:
        url = "https://localhost:10250/mock"
        mocker.get(
            url,
            text="mock"
        )

        return_value = FootholdViaSecureKubeletPort(anonymous_auth_enabled_event).get_request(url)

        assert return_value == "mock"


def test_get_request_invalid_url():
    anonymous_auth_enabled_event = AnonymousAuthEnabled()
    anonymous_auth_enabled_event.host = "localhost"

    with requests_mock.Mocker() as mocker:
        url = "https://localhost:10250/[mock]"
        mocker.get(
            url,
            exc=requests.exceptions.InvalidURL
        )

        return_value = FootholdViaSecureKubeletPort(anonymous_auth_enabled_event).get_request(url)

        assert return_value.startswith("Exception: ")


def post_request(url, params, expected_return_value, exception=None):
    with requests_mock.Mocker() as mocker:
        mock_params = {"text": "mock"} if not exception else {"exc": exception}
        mocker.post(
            url,
            **mock_params
        )

        return_value = FootholdViaSecureKubeletPort.post_request(
            url,
            params
        )

        assert return_value == expected_return_value


def test_post_request_valid_url_with_parameters():
    url = "https://localhost:10250/mock?cmd=ls"
    params = {"cmd": "ls"}
    post_request(url, params, expected_return_value="mock")


def test_post_request_valid_url_without_parameters():
    url = "https://localhost:10250/mock"
    params = {}
    post_request(url, params, expected_return_value="mock")


def test_post_request_invalid_url_with_parameters():
    url = "https://localhost:10250/mock?cmd=ls"
    params = {"cmd": "ls"}
    post_request(url, params, expected_return_value="Exception: ", exception=requests.exceptions.InvalidURL)


def test_post_request_invalid_url_without_parameters():
    url = "https://localhost:10250/mock"
    params = {}
    post_request(url, params, expected_return_value="Exception: ", exception=requests.exceptions.InvalidURL)


def test_has_no_exception_result_with_exception():
    mock_result = "Exception: Mock."

    return_value = FootholdViaSecureKubeletPort.has_no_exception(mock_result)

    assert return_value is False


def test_has_no_exception_result_without_exception():
    mock_result = "Mock."

    return_value = FootholdViaSecureKubeletPort.has_no_exception(mock_result)

    assert return_value is True


def test_has_no_error_result_with_error():
    mock_result = "Mock exited with error."

    return_value = FootholdViaSecureKubeletPort.has_no_error(mock_result)

    assert return_value is False


def test_has_no_error_result_without_error():
    mock_result = "Mock."

    return_value = FootholdViaSecureKubeletPort.has_no_error(mock_result)

    assert return_value is True


def test_has_no_error_nor_exception_result_without_exception_and_without_error():
    mock_result = "Mock."

    return_value = FootholdViaSecureKubeletPort.has_no_error_nor_exception(mock_result)

    assert return_value is True


def test_has_no_error_nor_exception_result_with_exception_and_without_error():
    mock_result = "Exception: Mock."

    return_value = FootholdViaSecureKubeletPort.has_no_error_nor_exception(mock_result)

    assert return_value is False


def test_has_no_error_nor_exception_result_without_exception_and_with_error():
    mock_result = "Mock exited with error."

    return_value = FootholdViaSecureKubeletPort.has_no_error_nor_exception(mock_result)

    assert return_value is False


def test_has_no_error_nor_exception_result_with_exception_and_with_error():
    mock_result = "Exception: Mock. Mock exited with error."

    return_value = FootholdViaSecureKubeletPort.has_no_error_nor_exception(mock_result)

    assert return_value is False


def footholdviasecurekubeletport_success(anonymous_auth_enabled_event, security_context_definition_to_test):
    global counter
    counter = 0

    with requests_mock.Mocker() as mocker:
        url = "https://" + anonymous_auth_enabled_event.host + ":10250/"
        listing_pods_url = url + "pods"
        run_url = url + "run/kube-hunter-privileged/kube-hunter-privileged-deployment-86dc79f945-sjjps/ubuntu?cmd="

        mocker.get(
            listing_pods_url,
            text=pod_list_with_privileged_container.replace(
                "{security_context_definition_to_test}",
                security_context_definition_to_test
            )
        )
        mocker.post(
            run_url + urllib.parse.quote(
                "cat /var/run/secrets/kubernetes.io/serviceaccount/token", safe=""),
            text=service_account_token
        )
        mocker.post(
            run_url + urllib.parse.quote(
                "cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt", safe=""),
            text=ca
        )
        mocker.post(
            run_url + "env",
            text=env
        )

        class_being_tested = FootholdViaSecureKubeletPort(anonymous_auth_enabled_event)
        class_being_tested.execute()

        assert "FootholdViaSecureKubeletPort: The following containers have been successfully breached." \
            in class_being_tested.event.evidence

    assert counter == 1


def test_footholdviasecurekubeletport_success_with_privileged_container_via_privileged_setting():
    anonymous_auth_enabled_event = AnonymousAuthEnabled()
    anonymous_auth_enabled_event.host = "localhost"

    footholdviasecurekubeletport_success(anonymous_auth_enabled_event, "\"privileged\": true")


def test_footholdviasecurekubeletport_success_with_privileged_container_via_capabilities():
    anonymous_auth_enabled_event = AnonymousAuthEnabled()
    anonymous_auth_enabled_event.host = "localhost"

    footholdviasecurekubeletport_success(anonymous_auth_enabled_event,
                                         "\"capabilities\": { \"add\": [\"SYS_ADMIN\"] }")


def test_footholdviasecurekubeletport_connectivity_issues():
    anonymous_auth_enabled_event = AnonymousAuthEnabled()
    anonymous_auth_enabled_event.host = "localhost"

    with requests_mock.Mocker() as mocker:
        url = "https://" + anonymous_auth_enabled_event.host + ":10250/"
        listing_pods_url = url + "pods"

        mocker.get(
            listing_pods_url,
            exc=requests.exceptions.ConnectionError
        )

        class_being_tested = FootholdViaSecureKubeletPort(anonymous_auth_enabled_event)
        class_being_tested.execute()

        assert class_being_tested.event.evidence == ""


@handler.subscribe(ExposedExistingPrivilegedContainersViaSecureKubeletPort)
class ExposedPrivilegedContainersViaAnonymousAuthEnabledInSecureKubeletPortEventCounter(object):
    def __init__(self, event):
        global counter
        counter += 1


def test_check_file_exists_existing_file():
    with requests_mock.Mocker() as mocker:
        url = "https://localhost:10250/"
        run_url = url + "run/kube-hunter-privileged/kube-hunter-privileged-deployment-86dc79f945-sjjps/ubuntu?cmd="
        mocker.post(
            run_url + urllib.parse.quote(
                "ls mock.txt", safe=""),
            text="mock.txt"
        )

        return_value = MaliciousIntentViaSecureKubeletPort.check_file_exists(
            url + "run/kube-hunter-privileged/kube-hunter-privileged-deployment-86dc79f945-sjjps/ubuntu",
            "mock.txt"
        )

        assert return_value is True


def test_check_file_exists_non_existent_file():
    with requests_mock.Mocker() as mocker:
        url = "https://localhost:10250/"
        run_url = url + "run/kube-hunter-privileged/kube-hunter-privileged-deployment-86dc79f945-sjjps/ubuntu?cmd="
        mocker.post(
            run_url + urllib.parse.quote(
                "ls nonexistentmock.txt", safe=""),
            text="ls: nonexistentmock.txt: No such file or directory"
        )

        return_value = MaliciousIntentViaSecureKubeletPort.check_file_exists(
            url + "run/kube-hunter-privileged/kube-hunter-privileged-deployment-86dc79f945-sjjps/ubuntu",
            "nonexistentmock.txt"
        )

        assert return_value is False


rm_command_removed_successfully_callback_counter = 0


def rm_command_removed_successfully_callback(request, context):
    global rm_command_removed_successfully_callback_counter

    if rm_command_removed_successfully_callback_counter == 0:
        rm_command_removed_successfully_callback_counter += 1
        return "mock.txt"
    else:
        return "ls: mock.txt: No such file or directory"


def test_rm_command_removed_successfully():
    with requests_mock.Mocker() as mocker:
        url = "https://localhost:10250/"
        run_url = url + "run/kube-hunter-privileged/kube-hunter-privileged-deployment-86dc79f945-sjjps/ubuntu?cmd="
        mocker.post(
            run_url + urllib.parse.quote(
                "ls mock.txt", safe=""),
            text=rm_command_removed_successfully_callback
        )
        mocker.post(
            run_url + urllib.parse.quote(
                "rm -f mock.txt", safe=""),
            text=""
        )

        return_value = MaliciousIntentViaSecureKubeletPort.rm_command(
            url + "run/kube-hunter-privileged/kube-hunter-privileged-deployment-86dc79f945-sjjps/ubuntu",
            "mock.txt",
            seconds_to_wait_for_os_command=None
        )

        assert return_value is True


def test_rm_command_removed_failed():
    with requests_mock.Mocker() as mocker:
        url = "https://localhost:10250/"
        run_url = url + "run/kube-hunter-privileged/kube-hunter-privileged-deployment-86dc79f945-sjjps/ubuntu?cmd="
        mocker.post(
            run_url + urllib.parse.quote(
                "ls mock.txt", safe=""),
            text="mock.txt"
        )
        mocker.post(
            run_url + urllib.parse.quote(
                "rm -f mock.txt", safe=""),
            text="Permission denied"
        )

        return_value = MaliciousIntentViaSecureKubeletPort.rm_command(
            url + "run/kube-hunter-privileged/kube-hunter-privileged-deployment-86dc79f945-sjjps/ubuntu",
            "mock.txt",
            seconds_to_wait_for_os_command=None
        )

        assert return_value is False


def create_test_event():
    exposed_existing_privileged_containers_via_secure_kubelet_port_event = \
        ExposedExistingPrivilegedContainersViaSecureKubeletPort(
            exposed_privileged_containers)
    exposed_existing_privileged_containers_via_secure_kubelet_port_event.host = "localhost"

    return exposed_existing_privileged_containers_via_secure_kubelet_port_event


def test_attack_exposed_existing_privileged_container_success():
    with requests_mock.Mocker() as mocker:
        url = "https://localhost:10250/"
        run_url = url + "run/kube-hunter-privileged/kube-hunter-privileged-deployment-86dc79f945-sjjps/ubuntu?cmd="
        directory_created = "/kube-hunter-mock_" + str(uuid.uuid1())
        file_name = "harmless-honestly-mock" + str(uuid.uuid1())
        file_name_with_path = "{}/etc/cron.daily/{}".format(
            directory_created,
            file_name
        )

        mocker.post(
            run_url + urllib.parse.quote(
                "touch {}".format(file_name_with_path), safe=""),
            text=""
        )
        mocker.post(
            run_url + urllib.parse.quote(
                "chmod {} {}".format("755", file_name_with_path), safe=""),
            text=""
        )

        class_being_tested = MaliciousIntentViaSecureKubeletPort(create_test_event())
        return_value = class_being_tested.attack_exposed_existing_privileged_container(
            url + "run/kube-hunter-privileged/kube-hunter-privileged-deployment-86dc79f945-sjjps/ubuntu",
            directory_created,
            None,
            file_name
        )

        assert return_value["result"] is True


def test_attack_exposed_existing_privileged_container_failure_when_touch():
    with requests_mock.Mocker() as mocker:
        directory_created = "/kube-hunter-mock_" + str(uuid.uuid1())
        file_name = "harmless-honestly-mock" + str(uuid.uuid1())
        file_name_with_path = "{}/etc/cron.daily/{}".format(
            directory_created,
            file_name
        )

        url = "https://localhost:10250/"
        run_url = url + "run/kube-hunter-privileged/kube-hunter-privileged-deployment-86dc79f945-sjjps/ubuntu?cmd="
        mocker.post(
            run_url + urllib.parse.quote(
                "touch {}".format(file_name_with_path), safe=""),
            text="Operation not permitted"
        )

        class_being_tested = MaliciousIntentViaSecureKubeletPort(create_test_event())
        return_value = class_being_tested.attack_exposed_existing_privileged_container(
            url + "run/kube-hunter-privileged/kube-hunter-privileged-deployment-86dc79f945-sjjps/ubuntu",
            directory_created,
            None,
            file_name
        )

        assert return_value["result"] is False


def test_attack_exposed_existing_privileged_container_failure_when_chmod():
    with requests_mock.Mocker() as mocker:
        directory_created = "/kube-hunter-mock_" + str(uuid.uuid1())
        file_name = "harmless-honestly-mock" + str(uuid.uuid1())
        file_name_with_path = "{}/etc/cron.daily/{}".format(
            directory_created,
            file_name
        )

        url = "https://localhost:10250/"
        run_url = url + "run/kube-hunter-privileged/kube-hunter-privileged-deployment-86dc79f945-sjjps/ubuntu?cmd="
        mocker.post(
            run_url + urllib.parse.quote(
                "touch {}".format(file_name_with_path), safe=""),
            text=""
        )
        mocker.post(
            run_url + urllib.parse.quote(
                "chmod {} {}".format("755", file_name_with_path), safe=""),
            text="Permission denied"
        )

        class_being_tested = MaliciousIntentViaSecureKubeletPort(create_test_event())
        return_value = class_being_tested.attack_exposed_existing_privileged_container(
            url + "run/kube-hunter-privileged/kube-hunter-privileged-deployment-86dc79f945-sjjps/ubuntu",
            directory_created,
            None,
            file_name
        )

        assert return_value["result"] is False


def test_check_directory_exists_existing_directory():
    with requests_mock.Mocker() as mocker:
        url = "https://localhost:10250/"
        run_url = url + "run/kube-hunter-privileged/kube-hunter-privileged-deployment-86dc79f945-sjjps/ubuntu?cmd="
        mocker.post(
            run_url + urllib.parse.quote(
                "ls Mock", safe=""),
            text="mock.txt"
        )

        return_value = MaliciousIntentViaSecureKubeletPort.check_directory_exists(
            url + "run/kube-hunter-privileged/kube-hunter-privileged-deployment-86dc79f945-sjjps/ubuntu",
            "Mock"
        )

        assert return_value is True


def test_check_directory_exists_non_existent_directory():
    with requests_mock.Mocker() as mocker:
        url = "https://localhost:10250/"
        run_url = url + "run/kube-hunter-privileged/kube-hunter-privileged-deployment-86dc79f945-sjjps/ubuntu?cmd="
        mocker.post(
            run_url + urllib.parse.quote(
                "ls Mock", safe=""),
            text="ls: Mock: No such file or directory"
        )

        return_value = MaliciousIntentViaSecureKubeletPort.check_directory_exists(
            url + "run/kube-hunter-privileged/kube-hunter-privileged-deployment-86dc79f945-sjjps/ubuntu",
            "Mock"
        )

        assert return_value is False


rmdir_command_removed_successfully_callback_counter = 0


def rmdir_command_removed_successfully_callback(request, context):
    global rmdir_command_removed_successfully_callback_counter

    if rmdir_command_removed_successfully_callback_counter == 0:
        rmdir_command_removed_successfully_callback_counter += 1
        return "mock.txt"
    else:
        return "ls: Mock: No such file or directory"


def test_rmdir_command_removed_successfully():
    with requests_mock.Mocker() as mocker:
        url = "https://localhost:10250/"
        run_url = url + "run/kube-hunter-privileged/kube-hunter-privileged-deployment-86dc79f945-sjjps/ubuntu?cmd="
        mocker.post(
            run_url + urllib.parse.quote(
                "ls Mock", safe=""),
            text=rmdir_command_removed_successfully_callback
        )
        mocker.post(
            run_url + urllib.parse.quote(
                "rmdir Mock", safe=""),
            text=""
        )

        return_value = MaliciousIntentViaSecureKubeletPort.rmdir_command(
            url + "run/kube-hunter-privileged/kube-hunter-privileged-deployment-86dc79f945-sjjps/ubuntu",
            "Mock",
            seconds_to_wait_for_os_command=None
        )

        assert return_value is True


def test_rmdir_command_removed_failed():
    with requests_mock.Mocker() as mocker:
        url = "https://localhost:10250/"
        run_url = url + "run/kube-hunter-privileged/kube-hunter-privileged-deployment-86dc79f945-sjjps/ubuntu?cmd="
        mocker.post(
            run_url + urllib.parse.quote(
                "ls Mock", safe=""),
            text="mock.txt"
        )
        mocker.post(
            run_url + urllib.parse.quote(
                "rmdir Mock", safe=""),
            text="Permission denied"
        )

        return_value = MaliciousIntentViaSecureKubeletPort.rmdir_command(
            url + "run/kube-hunter-privileged/kube-hunter-privileged-deployment-86dc79f945-sjjps/ubuntu",
            "Mock",
            seconds_to_wait_for_os_command=None
        )

        assert return_value is False


def test_get_root_values_success():
    class_being_tested = MaliciousIntentViaSecureKubeletPort(create_test_event(), None)
    root_value, root_value_type = class_being_tested.get_root_values(cat_proc_cmdline)

    assert root_value == "Mock" and root_value_type == "LABEL="


def test_get_root_values_failure():
    class_being_tested = MaliciousIntentViaSecureKubeletPort(create_test_event(), None)
    root_value, root_value_type = class_being_tested.get_root_values("")

    assert root_value is None and root_value_type is None


def test_process_exposed_existing_privileged_container_success():
    with requests_mock.Mocker() as mocker:
        url = "https://localhost:10250/"
        run_url = url + "run/kube-hunter-privileged/kube-hunter-privileged-deployment-86dc79f945-sjjps/ubuntu?cmd="
        directory_created = "/kube-hunter-mock_" + str(uuid.uuid1())

        mocker.post(
            run_url + urllib.parse.quote(
                "cat /proc/cmdline", safe=""),
            text=cat_proc_cmdline
        )
        mocker.post(
            run_url + urllib.parse.quote(
                "findfs LABEL=Mock", safe=""),
            text="/dev/mock_fs"
        )
        mocker.post(
            run_url + urllib.parse.quote(
                "mkdir {}".format(directory_created), safe=""),
            text=""
        )
        mocker.post(
            run_url + urllib.parse.quote(
                "mount {} {}".format("/dev/mock_fs", directory_created), safe=""),
            text=""
        )
        mocker.post(
            run_url + urllib.parse.quote(
                "cat {}/etc/hostname".format(directory_created), safe=""),
            text="mockhostname"
        )

        class_being_tested = MaliciousIntentViaSecureKubeletPort(create_test_event())
        return_value = class_being_tested.process_exposed_existing_privileged_container(
            url + "run/kube-hunter-privileged/kube-hunter-privileged-deployment-86dc79f945-sjjps/ubuntu",
            None,
            directory_created
        )

        assert return_value["result"] is True


def test_process_exposed_existing_privileged_container_failure_when_cat_cmdline():
    with requests_mock.Mocker() as mocker:
        url = "https://localhost:10250/"
        run_url = url + "run/kube-hunter-privileged/kube-hunter-privileged-deployment-86dc79f945-sjjps/ubuntu?cmd="
        directory_created = "/kube-hunter-mock_" + str(uuid.uuid1())

        mocker.post(
            run_url + urllib.parse.quote(
                "cat /proc/cmdline", safe=""),
            text="Permission denied"
        )

        class_being_tested = MaliciousIntentViaSecureKubeletPort(create_test_event())
        return_value = class_being_tested.process_exposed_existing_privileged_container(
            url + "run/kube-hunter-privileged/kube-hunter-privileged-deployment-86dc79f945-sjjps/ubuntu",
            None,
            directory_created
        )

        assert return_value["result"] is False


def test_process_exposed_existing_privileged_container_failure_when_findfs():
    with requests_mock.Mocker() as mocker:
        url = "https://localhost:10250/"
        run_url = url + "run/kube-hunter-privileged/kube-hunter-privileged-deployment-86dc79f945-sjjps/ubuntu?cmd="
        directory_created = "/kube-hunter-mock_" + str(uuid.uuid1())

        mocker.post(
            run_url + urllib.parse.quote(
                "cat /proc/cmdline", safe=""),
            text=cat_proc_cmdline
        )
        mocker.post(
            run_url + urllib.parse.quote(
                "findfs LABEL=Mock", safe=""),
            text="Permission denied"
        )

        class_being_tested = MaliciousIntentViaSecureKubeletPort(create_test_event())
        return_value = class_being_tested.process_exposed_existing_privileged_container(
            url + "run/kube-hunter-privileged/kube-hunter-privileged-deployment-86dc79f945-sjjps/ubuntu",
            None,
            directory_created
        )

        assert return_value["result"] is False


def test_process_exposed_existing_privileged_container_failure_when_mkdir():
    with requests_mock.Mocker() as mocker:
        url = "https://localhost:10250/"
        run_url = url + "run/kube-hunter-privileged/kube-hunter-privileged-deployment-86dc79f945-sjjps/ubuntu?cmd="
        directory_created = "/kube-hunter-mock_" + str(uuid.uuid1())

        mocker.post(
            run_url + urllib.parse.quote(
                "cat /proc/cmdline", safe=""),
            text=cat_proc_cmdline
        )
        mocker.post(
            run_url + urllib.parse.quote(
                "findfs LABEL=Mock", safe=""),
            text="/dev/mock_fs"
        )
        mocker.post(
            run_url + urllib.parse.quote(
                "mkdir {}".format(directory_created), safe=""),
            text="Permission denied"
        )

        class_being_tested = MaliciousIntentViaSecureKubeletPort(create_test_event())
        return_value = class_being_tested.process_exposed_existing_privileged_container(
            url + "run/kube-hunter-privileged/kube-hunter-privileged-deployment-86dc79f945-sjjps/ubuntu",
            None,
            directory_created
        )

        assert return_value["result"] is False


def test_process_exposed_existing_privileged_container_failure_when_mount():
    with requests_mock.Mocker() as mocker:
        url = "https://localhost:10250/"
        run_url = url + "run/kube-hunter-privileged/kube-hunter-privileged-deployment-86dc79f945-sjjps/ubuntu?cmd="
        directory_created = "/kube-hunter-mock_" + str(uuid.uuid1())

        mocker.post(
            run_url + urllib.parse.quote(
                "cat /proc/cmdline", safe=""),
            text=cat_proc_cmdline
        )
        mocker.post(
            run_url + urllib.parse.quote(
                "findfs LABEL=Mock", safe=""),
            text="/dev/mock_fs"
        )
        mocker.post(
            run_url + urllib.parse.quote(
                "mkdir {}".format(directory_created), safe=""),
            text=""
        )
        mocker.post(
            run_url + urllib.parse.quote(
                "mount {} {}".format("/dev/mock_fs", directory_created), safe=""),
            text="Permission denied"
        )

        class_being_tested = MaliciousIntentViaSecureKubeletPort(create_test_event())
        return_value = class_being_tested.process_exposed_existing_privileged_container(
            url + "run/kube-hunter-privileged/kube-hunter-privileged-deployment-86dc79f945-sjjps/ubuntu",
            None,
            directory_created
        )

        assert return_value["result"] is False


def test_process_exposed_existing_privileged_container_failure_when_cat_hostname():
    with requests_mock.Mocker() as mocker:
        url = "https://localhost:10250/"
        run_url = url + "run/kube-hunter-privileged/kube-hunter-privileged-deployment-86dc79f945-sjjps/ubuntu?cmd="
        directory_created = "/kube-hunter-mock_" + str(uuid.uuid1())

        mocker.post(
            run_url + urllib.parse.quote(
                "cat /proc/cmdline", safe=""),
            text=cat_proc_cmdline
        )
        mocker.post(
            run_url + urllib.parse.quote(
                "findfs LABEL=Mock", safe=""),
            text="/dev/mock_fs"
        )
        mocker.post(
            run_url + urllib.parse.quote(
                "mkdir {}".format(directory_created), safe=""),
            text=""
        )
        mocker.post(
            run_url + urllib.parse.quote(
                "mount {} {}".format("/dev/mock_fs", directory_created), safe=""),
            text=""
        )
        mocker.post(
            run_url + urllib.parse.quote(
                "cat {}/etc/hostname".format(directory_created), safe=""),
            text="Permission denied"
        )

        class_being_tested = MaliciousIntentViaSecureKubeletPort(create_test_event())
        return_value = class_being_tested.process_exposed_existing_privileged_container(
            url + "run/kube-hunter-privileged/kube-hunter-privileged-deployment-86dc79f945-sjjps/ubuntu",
            None,
            directory_created
        )

        assert return_value["result"] is False


def test_maliciousintentviasecurekubeletport_success():
    with requests_mock.Mocker() as mocker:
        url = "https://localhost:10250/"
        run_url = url + "run/kube-hunter-privileged/kube-hunter-privileged-deployment-86dc79f945-sjjps/ubuntu?cmd="
        directory_created = "/kube-hunter-mock_" + str(uuid.uuid1())
        file_name = "harmless-honestly-mock" + str(uuid.uuid1())
        file_name_with_path = "{}/etc/cron.daily/{}".format(
            directory_created,
            file_name
        )

        mocker.post(
            run_url + urllib.parse.quote(
                "cat /proc/cmdline", safe=""),
            text=cat_proc_cmdline
        )
        mocker.post(
            run_url + urllib.parse.quote(
                "findfs LABEL=Mock", safe=""),
            text="/dev/mock_fs"
        )
        mocker.post(
            run_url + urllib.parse.quote(
                "mkdir {}".format(directory_created), safe=""),
            text=""
        )
        mocker.post(
            run_url + urllib.parse.quote(
                "mount {} {}".format("/dev/mock_fs", directory_created), safe=""),
            text=""
        )
        mocker.post(
            run_url + urllib.parse.quote(
                "cat {}/etc/hostname".format(directory_created), safe=""),
            text="mockhostname"
        )
        mocker.post(
            run_url + urllib.parse.quote(
                "touch {}".format(file_name_with_path), safe=""),
            text=""
        )
        mocker.post(
            run_url + urllib.parse.quote(
                "chmod {} {}".format("755", file_name_with_path), safe=""),
            text=""
        )

        class_being_tested = MaliciousIntentViaSecureKubeletPort(create_test_event(), None)
        class_being_tested.execute(
            directory_created,
            file_name
        )

        message = "The following exposed existing privileged containers have been successfully"
        message += " abused by starting/modifying a process in the host."

        assert message in class_being_tested.event.evidence
