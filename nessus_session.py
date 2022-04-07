import json
from itertools import chain
from argparse import ArgumentParser

import requests
from warnings import filterwarnings
filterwarnings('ignore')


class NessusSession(requests.Session):
    def __init__(self, host, scan_number, accessKey, secretKey, port=8834):
        requests.Session.__init__(self)
        self.headers['X-ApiKeys'] = 'accessKey={}; secretKey={}'.format(
            accessKey, secretKey
        )
        self.root = 'https://{}:{}/scans/{}'.format(host, port, scan_number)
        self.verify = False
    
    def request(self, method, url, **kwargs):
        # requests only ever go to the nessus server, so bake that in
        url = self.root+url
        return requests.Session.request(self, method, url, **kwargs)

    def plugin_hosts(self, plugin_id):
        # get all the individual hosts associated with a given plugin
        resp = self.get('/plugins/{}'.format(plugin_id))
        dat = resp.json()
        # use a set comprehension to eliminate repeats
        return {
            *chain(*((h['hostname'] for h in p)
                     for p in dat['outputs'][0]['ports'].values()))
        }
            


def nessus_script_arg_parse(description='default description'):
    parser = ArgumentParser(description)
    parser.add_argument('scan_no', type=int, help="number of scan to analyze")
    parser.add_argument('NessusHost', type=str, help="address of nessus service")
    parser.add_argument('ApiKey', type=str, help="nessus api key")
    parser.add_argument('SecretKey', type=str, help="nessus secret key")

    return parser
    

