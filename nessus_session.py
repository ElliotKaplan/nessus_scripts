import json
from argparse import ArgumentParser

import requests
from warnings import filterwarnings
filterwarnings('ignore')


class NessusSession(requests.Session):
    def __init__(self, host, accessKey, secretKey, port=8834):
        requests.Session.__init__(self)
        self.headers['X-ApiKeys'] = 'accessKey={}; secretKey={}'.format(
            accessKey, secretKey
        )
        self.domain = 'https://{}:{}'.format(host, port)
        self.verify = False
    
    def request(self, method, url, **kwargs):
        url = self.domain + url
        return requests.Session.request(self, method, url, **kwargs)


def nessus_script_arg_parse(description='default description'):
    parser = ArgumentParser(description)
    parser.add_argument('scan_no', type=int, help="number of scan to analyze")
    parser.add_argument('NessusHost', type=str, help="address of nessus service")
    parser.add_argument('ApiKey', type=str, help="nessus api key")
    parser.add_argument('SecretKey', type=str, help="nessus secret key")

    return parser.parse_args()
    
