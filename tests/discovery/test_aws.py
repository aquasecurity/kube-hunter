# import requests_mock

# class TestAwsMetadataApiDiscovery:
#     @staticmethod
#     def _make_aws_response(*data: List[str]) -> str:
#         return "\n".join(data)


#     def test_is_aws_pod_v1_success(self):
#         f = FromPodHostDiscovery(RunningAsPodEvent())

#         with requests_mock.Mocker() as m:
#             m.get(
#                 "http://169.254.169.254/latest/meta-data/",
#                 text=TestFromPodHostDiscovery._make_aws_response(
#                     "\n".join(
#                         (
#                             "ami-id",
#                             "ami-launch-index",
#                             "ami-manifest-path",
#                             "block-device-mapping/",
#                             "events/",
#                             "hostname",
#                             "iam/",
#                             "instance-action",
#                             "instance-id",
#                             "instance-type",
#                             "local-hostname",
#                             "local-ipv4",
#                             "mac",
#                             "metrics/",
#                             "network/",
#                             "placement/",
#                             "profile",
#                             "public-hostname",
#                             "public-ipv4",
#                             "public-keys/",
#                             "reservation-id",
#                             "security-groups",
#                             "services/",
#                         )
#                     ),
#                 ),
#             )
#             result = f.is_aws_pod_v1()

#         assert result

#     def test_is_aws_pod_v2_request_fail(self):
#         f = FromPodHostDiscovery(RunningAsPodEvent())

#         with requests_mock.Mocker() as m:
#             m.put(
#                 "http://169.254.169.254/latest/api/token/",
#                 headers={"X-aws-ec2-metatadata-token-ttl-seconds": "21600"},
#                 status_code=404,
#             )
#             m.get(
#                 "http://169.254.169.254/latest/meta-data/",
#                 headers={"X-aws-ec2-metatadata-token": "token"},
#                 status_code=404,
#             )
#             result = f.is_aws_pod_v2()

#         assert not result

#     def test_is_aws_pod_v2_success(self):
#         f = FromPodHostDiscovery(RunningAsPodEvent())

#         with requests_mock.Mocker() as m:
#             m.put(
#                 "http://169.254.169.254/latest/api/token/",
#                 headers={"X-aws-ec2-metatadata-token-ttl-seconds": "21600"},
#                 text=TestFromPodHostDiscovery._make_aws_response("token"),
#             )
#             m.get(
#                 "http://169.254.169.254/latest/meta-data/",
#                 headers={"X-aws-ec2-metatadata-token": "token"},
#                 text=TestFromPodHostDiscovery._make_aws_response(
#                     "\n".join(
#                         (
#                             "ami-id",
#                             "ami-launch-index",
#                             "ami-manifest-path",
#                             "block-device-mapping/",
#                             "events/",
#                             "hostname",
#                             "iam/",
#                             "instance-action",
#                             "instance-id",
#                             "instance-type",
#                             "local-hostname",
#                             "local-ipv4",
#                             "mac",
#                             "metrics/",
#                             "network/",
#                             "placement/",
#                             "profile",
#                             "public-hostname",
#                             "public-ipv4",
#                             "public-keys/",
#                             "reservation-id",
#                             "security-groups",
#                             "services/",
#                         )
#                     ),
#                 ),
#             )
#             result = f.is_aws_pod_v2()

#         assert result

