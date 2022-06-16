#!/usr/bin/python3

from nessus_session import NessusSession, nessus_script_arg_parse


if __name__=='__main__':
    parser = nessus_script_arg_parse('Find outdated operating systems/software in a given nessus scan')
    clargs = parser.parse_args()
    sess = NessusSession(clargs.NessusHost, clargs.scan_no, clargs.ApiKey, clargs.SecretKey, history_id=clargs.history_id)
    print(sess.scan_name())
