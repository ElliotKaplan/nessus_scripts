#!/usr/bin/python3
from itertools import chain
import json
import time

import requests

from nessus_session import NessusScanSession, nessus_scan_script_arg_parse


if __name__=='__main__':
    parser = nessus_scan_script_arg_parse('Download a specific nessus scan')
    parser.add_argument('fileName', type=str, help="Name of download file")
    
    clargs = parser.parse_args()
    sess = NessusScanSession(clargs.scan_no, clargs.NessusHost, clargs.AccessKey, clargs.SecretKey, history_id=clargs.history_id)

    resp = sess.post('/export', json={'format': clargs.fileName.split('.')[-1]})
    tokens = resp.json()['token']
    nessus_server = '/'.join(sess.root.split('/', 3)[:-1])
    # wait til the download is ready
    while True:
        resp = requests.get('{}/tokens/{}/download'.format(nessus_server, tokens), verify=False)
        try:
            status = resp.json()['status']
            if status == 'loading':
                time.sleep(2)
                continue
        except KeyError:
            break
        except json.decoder.JSONDecodeError:
            break
    
    with open(clargs.fileName, 'wb') as fi:
        fi.write(resp.content)
