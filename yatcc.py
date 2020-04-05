#!/usr/bin/env python3
import base64
import hashlib
import hmac
import json
import time
from urllib.parse import urlparse

import requests


def custom_requests_user_agent(ua_str):
    """custom requests user agent with requests version"""
    return "{} ({})".format(
        ua_str,
        requests.utils.default_headers().get('User-Agent', "python-requests")
    )


class ThreatConnectClient:
    """TC API config setup and request methods"""
    DEFAULT_ORG = "Common Community"
    DEFAULT_LOGGING = "critical"

    USER_AGENT = custom_requests_user_agent("yaTCc")

    def __init__(self,
        access_id,
        secret_key,
        api_url="https://api.threatconnect.com",
        default_org=DEFAULT_ORG,
        log_level=DEFAULT_LOGGING
    ):
        self.access_id = access_id
        self.secret_key = secret_key
        self.api_url = api_url
        self.default_org = default_org
        self.log_level = log_level


    def tc_auth_sig(self, url_path, method, timestamp):
        message = "{}:{}:{}".format(url_path, method, timestamp)
        signature = hmac.new(
                        self.secret_key.encode(),
                        message.encode(),
                        digestmod=hashlib.sha256
                    ).digest()
        return base64.b64encode(signature).decode()


    def tc_request_headers(self, url_path, method):
        timestamp = int(time.time())
        signature = self.tc_auth_sig(url_path, method, timestamp)
        return {
            'Timestamp': str(timestamp),
            'Authorization': "TC {}:{}".format(self.access_id, signature),
            'User-Agent': self.USER_AGENT,
        }


    def tc_request(self, path, method):
        url = self.api_url + path

        # parse full path from config base url + request - required for supporting private API paths
        url_path = urlparse(url).path
        return requests.get(url, headers=self.tc_request_headers(url_path, method))

# https://docs.threatconnect.com/en/latest/rest_api/overview.html#api-overview


def tc_config_json(tc_config_file):
    with open(tc_config_file, 'r') as f:
        try:
            conf = json.load(f)
        except Exception as e:
            print("Error reading TC config json file", e)
            return -1
    return ThreatConnectClient(
        conf["api_access_id"],
        conf["api_secret_key"],
        conf["tc_api_path"],
        conf.get("api_default_org", ThreatConnectClient.DEFAULT_ORG),
        conf.get("tc_log_level", ThreatConnectClient.DEFAULT_LOGGING)
    )
