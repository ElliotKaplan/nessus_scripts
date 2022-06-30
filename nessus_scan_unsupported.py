#!/usr/bin/python3
from itertools import chain

from nessus_session import NessusScanSession, nessus_scan_script_arg_parse

def get_unsupported(sess):
    resp = sess.get('')
    dat = resp.json()
    # find results labeled 'unsupported'
    unsup = {
        d['plugin_name']: d['plugin_id']
        for d in dat['vulnerabilities']
        if 'unsupported' in d['plugin_name'].lower()
    }
    return {k: sess.plugin_hosts(v) for k, v in unsup.items()}

        
if __name__=='__main__':
    parser = nessus_scan_script_arg_parse('Find outdated operating systems/software in a given nessus scan')
    parser.add_argument('-nc', '--num_col', type=int, default=3, help='number of columns for output')
    clargs = parser.parse_args()

    sess = NessusScanSession(clargs.scan_no, clargs.NessusHost, clargs.AccessKey, clargs.SecretKey)
    scan = get_unsupported(sess)
    for key, hosts in scan.items():
        print(key)
        width = max(map(len, hosts)) + 5
        fmtstr = ('{:<' + str(width) + 's}')*clargs.num_col
        hosts = sorted(hosts, key=lambda h: list(map(int, h.split('.'))))
        nrow = len(hosts)//clargs.num_col + 1
        cols = [hosts[i*nrow:(i+1)*nrow] for i in range(clargs.num_col)]
        for col in cols[1:]:
            while len(col) != len(cols[0]):
                col.append('')
        print('\n'.join(fmtstr.format(*r) for r in zip(*cols)))
        
        print('='*32)


