
import json
from os import environ
from itertools import chain
from argparse import ArgumentParser

import requests
from warnings import filterwarnings
filterwarnings('ignore')

class NessusSession(requests.Session):
    def __init__(
            self,
            host=environ.get('NESSUS_HOST', 'localhost'),
            accessKey=environ.get('ACCESS_KEY', ''),
            secretKey=environ.get('SECRET_KEY', ''),
            port=environ.get('NESSUS_PORT', 8834)
    ):
        requests.Session.__init__(self)
        self.verify = False
        self.headers['X-ApiKeys'] = 'accessKey={}; secretKey={}'.format(
            accessKey, secretKey
        )
        self.root = 'https://{}:{}/'.format(host, port)

    def request(self, method, url, **kwargs):
        url = self.root + url
        return requests.Session.request(self, method, url, **kwargs)

class NessusScanSession(NessusSession):
    def __init__(self, scan_number, *args, history_id=None, **kwargs):
        NessusSession.__init__(self, *args, **kwargs)
        self.root += 'scans/{}'.format(scan_number)
        self.base_query = {'history_id': history_id}

    # def request(self, method, url, **kwargs):
    #     # requests only ever go to the nessus server, so bake that in
    #     url = self.root+url
    #     params = kwargs.get('params')
    #     if params is not None:
    #         params.update(**self.base_query)
    #     else:
    #         params = self.base_query
    #     return requests.Session.request(self, method, url, params=params, **kwargs)
    def request(self, method, url, **kwargs):
        # requests only ever go to the nessus server, so bake that in
        url = self.root+url
        return requests.Session.request(self, method, url, **kwargs)

    def plugin_hosts(self, plugin_id):
        # get all the individual hosts associated with a given plugin
        resp = self.get('/plugins/{}'.format(plugin_id))
        data = resp.json()
        # use a set comprehension to eliminate repeats
        return {
            *chain(
                (
                    h['hostname'] 
                    for d in data['outputs']
                    for p in d['ports'].values()
                    for h in p
                )
            )
        }

    def scan_name(self):
        resp = self.get('')
        data = resp.json()
        return data['info']['name']


def nessus_script_arg_parse(description='default description'):
    parser = ArgumentParser(description)
    if environ.get('NESSUS_HOST') is not None:
        parser.add_argument('--NessusHost', type=str,
                            default=environ.get('NESSUS_HOST'),
                            help="address of nessus service")
    else:
        parser.add_argument('NessusHost', type=str,
                            help="address of nessus service")
    if environ.get('ACCESS_KEY') is not None:
        parser.add_argument('--AccessKey', type=str,
                            default=environ.get('ACCESS_KEY'),
                            help="nessus api key")
    else:
        parser.add_argument('AccessKey', type=str,
                            help="nessus api key")
    if environ.get('SECRET_KEY') is not None:
        parser.add_argument('--SecretKey', type=str,
                            default=environ.get('SECRET_KEY'),
                            help="nessus secret key")
    else:
        parser.add_argument('SecretKey', type=str,
                            help="nessus secret key")
    return parser

def nessus_scan_script_arg_parse(description='default description'):
    parser = nessus_script_arg_parse(description)
    parser.add_argument('scan_no', type=int, help="number of scan to analyze")
    parser.add_argument('-hid', '--history_id', default=None, type=int, help="history id of scan")
    return parser
