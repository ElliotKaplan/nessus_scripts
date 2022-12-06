#!/usr/bin/python3
from nessus_session import NessusScanSession, nessus_scan_script_arg_parse

if __name__=='__main__':
    parser = nessus_scan_script_arg_parse('List the hosts in a given nessus scan')
    clargs = parser.parse_args()
    sess = NessusScanSession(clargs.scan_no, clargs.NessusHost, clargs.AccessKey, clargs.SecretKey, history_id=clargs.history_id)
    resp = sess.get('')
    dat = resp.json()
    print('\n'.join(h['hostname'] for h in dat['hosts']))

