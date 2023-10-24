#!/usr/bin/python3
from nessus_session import NessusScanSession, nessus_scan_script_arg_parse


if __name__=='__main__':
    parser = nessus_scan_script_arg_parse('Find outdated operating systems/software in a given nessus scan')
    parser.add_argument('-nc', '--num_col', type=int, default=3, help='number of columns for output')
    clargs = parser.parse_args()

    sess = NessusScanSession(clargs.scan_no, clargs.NessusHost, clargs.AccessKey, clargs.SecretKey)
    sess.post('/launch')
