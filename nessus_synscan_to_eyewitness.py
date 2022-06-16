#!/usr/bin/python3
from collections import defaultdict

from nessus_session import NessusSession, nessus_script_arg_parse

def get_synscan(sess):
    synscan = sess.get('/plugins/11219').json()
    # organize the output by port
    ports = defaultdict(set)
    for output in synscan['outputs']:
        for port, arr in output['ports'].items():
            port = int(port.split()[0])
            ports[port].update({h['hostname'] for h in arr})
    
    # check the tls/ssl plugins to sort out encrypted ports
    sslvers = sess.get('/plugins/56984').json()
    sslports = defaultdict(set)
    for output in sslvers['outputs']:
        for port, arr in output['ports'].items():
            port = int(port.split()[0])
            sslports[port].update({h['hostname'] for h in arr})
            
    out = list()
    for port, hosts in ports.items():
        if port == 21:
            out += ['ftp://{}'.format(h['hostname']) for h in arr]
            continue
        elif port == 80:
            out += ['http://{}'.format(h['hostname']) for h in arr]
            continue
        elif port == 443:
            out += ['https://{}'.format(h['hostname']) for h in arr]
            continue
        elif port == 3389:
            out += ['rdp://{}'.format(h['hostname']) for h in arr]
            continue
        # drop any port under 1000 as probably not an http(s) port
        elif port < 1000:
            continue
        enc = sslports[port]
        unenc = hosts.difference(enc)
        out += ['http://{}:{}'.format(h, port) for h in unenc]
        out += ['https://{}:{}'.format(h, port) for h in enc]
        
    return out

if __name__=='__main__':
    parser = nessus_script_arg_parse('convert a syn scan to a file compatable with Eyewitness')
    clargs = parser.parse_args()
    
    sess = NessusSession(clargs.NessusHost, clargs.scan_no, clargs.ApiKey, clargs.SecretKey, history_id=clargs.history_id)
    scan = get_synscan(sess)
    print('\n'.join(scan))
    
