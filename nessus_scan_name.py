#!/usr/bin/python3

from nessus_session import NessusScanSession, nessus_scan_script_arg_parse


if __name__=='__main__':
    parser = nessus_scan_script_arg_parse('Find outdated operating systems/software in a given nessus scan')
    clargs = parser.parse_args()
    sess = NessusScanSession(clargs.scan_no, clargs.NessusHost, clargs.ApiKey, clargs.SecretKey, history_id=clargs.history_id)
    print(sess.scan_name())
