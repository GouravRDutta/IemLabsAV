

import requests
import time
from iemlav.lib.auto_server_patcher.patch_logger import PatchLogger


class SSLScanner(object):
    """SSLScanner class."""

    def __init__(self, debug=False, url=None):

        # Initialize logger
        self.logger = PatchLogger(
            __name__,
            debug=debug
        )

        # API URL
        self._API_URL = "https://api.ssllabs.com/api/v3/analyze/"

        self.analyze_payload = {
            'startNew': 'on',
            'publish': 'off',
            'all': 'done',
            'ignoreMismatch': 'on'
        }

        # URL / website to scan
        self.url = str(url)

    @staticmethod
    def request_api(url, payload):

        resp = requests.get(url, params=payload)
        return resp.json()

    def analyze(self):

        self.analyze_payload.update({'host' : self.url})
        # Start analyzing the website
        self.logger.log(
            "Analyzing URL: " + self.url,
            logtype="info"
        )
        resp = self.request_api(self._API_URL, self.analyze_payload)
        self.analyze_payload.pop('startNew')

        while resp['status'] != 'READY' and resp['status'] != 'ERROR':
            time.sleep(15)
            resp = self.request_api(self._API_URL, self.analyze_payload)

        return resp

    @staticmethod
    def vulnerability_parser(data):

        base_data = data['endpoints'][0]['details']

        # Parse the API data into a dict
        vuln_dict = {
            'beastAttack': base_data['vulnBeast'],
            'poodle': base_data['poodle'],
            'poodleTls': base_data['poodleTls'],
            'rc4': base_data['rc4Only'],
            'heartbeat': base_data['heartbeat'],
            'heartbleed': base_data['heartbleed'],
            'ticketbleed': base_data['ticketbleed'],
            'openSSL_CCS': base_data['openSslCcs'],
            'openSSL_padding': base_data['openSSLLuckyMinus20'],
            'robot': base_data['bleichenbacher'],
            'freak': base_data['freak'],
            'logjam': base_data['logjam'],
            'drown_attack': base_data['drownVulnerable'],
        }

        return vuln_dict

    @staticmethod
    def get_value(key, value):

        main_dict = {
                'poodleTls': {
                    '-3': 'timeout',
                    '-2': 'TLS not supported',
                    '-1': 'test failed',
                    '0': 'unknown',
                    '1': 'not vulnerable',
                    '2': 'vulnerable'
                },
                'ticketbleed': {
                    '-1': 'test failed',
                    '0': 'unknown',
                    '1': 'not vulnerable',
                    '2': 'vulnerable and insecure'
                },
                'openSSL_CCS': {
                    '-1': 'test failed',
                    '0': 'unknown',
                    '1': 'not vulnerable',
                    '2': 'possibly vulnerable, but not exploitable',
                    '3': 'vulnerable and exploitable'
                },
                'openSSL_padding': {
                    '-1': 'test failed',
                    '0': 'unknown',
                    '1': 'not vulnerable',
                    '2': 'vulnerable and insecure'
                },
                'robot': {
                    '-1': 'test failed',
                    '0': 'unknown',
                    '1': 'not vulnerable',
                    '2': 'vulnerable (weak oracle)',
                    '3': 'vulnerable (strong oracle)',
                    '4': 'inconsistent results'
                }
        }

        value = str(value)
        return main_dict[key][value]

    def log_data(self, dict_value):

        self.logger.log(
            "Vulnerability Scan Result: " + self.url,
            logtype="info"
        )

        for vuln, res in dict_value.items():
            if not isinstance(res, bool):
                res = self.get_value(vuln, res)
            self.logger.log(
                str(vuln) + ": " + str(res),
                logtype="info"
            )

    def start_scan(self):


        # Start analyzing
        resp = self.analyze()
        # Parse the result
        parsed_resp = self.vulnerability_parser(resp)
        # Log the parsed data
        self.log_data(parsed_resp)
