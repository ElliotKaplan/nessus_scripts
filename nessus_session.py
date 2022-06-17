import json
from itertools import chain
from argparse import ArgumentParser

import requests
from warnings import filterwarnings
filterwarnings('ignore')

class NessusSession(requests.Session):
    def __init__(self, host, accessKey, secretKey, port=8834):
        requests.Session.__init__(self)
        self.verify = False
        self.headers['X-ApiKeys'] = 'accessKey={}; secretKey={}'.format(
            accessKey, secretKey
        )
        self.root = 'https://{}:{}/'.format(host, port)

class NessusScanSession(NessusSession):
    def __init__(self, scan_number, *args, history_id=None, **kwargs):
        NessusSession.__init__(self, *args, **kwargs)
        self.root += 'scans/{}'.format(scan_number)
        self.base_query = {'history_id': history_id}

    def request(self, method, url, **kwargs):
        # requests only ever go to the nessus server, so bake that in
        url = self.root+url
        params = kwargs.get('params')
        if params is not None:
            params.update(**self.base_query)
        else:
            params = self.base_query
        return requests.Session.request(self, method, url, params=params, **kwargs)

    def plugin_hosts(self, plugin_id):
        # get all the individual hosts associated with a given plugin
        resp = self.get('/plugins/{}'.format(plugin_id))
        dat = resp.json()
        # use a set comprehension to eliminate repeats
        return {
            *chain(*((h['hostname'] for h in p)
                     for p in dat['outputs'][0]['ports'].values()))
        }

    def scan_name(self):
        resp = self.get('')
        dat = resp.json()
        return dat['info']['name']


def nessus_script_arg_parse(description='default description'):
    parser = ArgumentParser(description)
    parser.add_argument('NessusHost', type=str, help="address of nessus service")
    parser.add_argument('ApiKey', type=str, help="nessus api key")
    parser.add_argument('SecretKey', type=str, help="nessus secret key")
    return parser

def nessus_scan_script_arg_parse(description='default description'):
    parser = nessus_script_arg_parse(description)
    parser.add_argument('scan_no', type=int, help="number of scan to analyze")
    parser.add_argument('-hid', '--history_id', default=None, type=int, help="history id of scan")
    return parser
