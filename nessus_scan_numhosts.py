#!/usr/bin/python3
from nessus_session import NessusScanSession, nessus_scan_script_arg_parse

if __name__=='__main__':
    parser = nessus_scan_script_arg_parse('Find get the number of hosts in a given nessus scan')
    clargs = parser.parse_args()
    sess = NessusScanSession(clargs.scan_no, clargs.NessusHost, clargs.ApiKey, clargs.SecretKey, history_id=clargs.history_id)
    resp = sess.get('')
    dat = resp.json()
    print(clargs.scan_no, '\t', dat['info']['name'], '\t', len(dat['hosts']))
