#!/usr/bin/python3
import json

from nessus_session import NessusSession, nessus_script_arg_parse

if __name__=='__main__':
    parser = nessus_script_arg_parse('Find outdated operating systems/software in a given nessus scan')
    parser.add_argument('folder_id', type=int, help="number of folder to read")
    parser.add_argument('-d', '--descending', action='store_true',
                        help='set to sort output by count descending')
    parser.add_argument('-a', '--alphasort', action='store_true',
                        help='set to sort output alphabetially')
    parser.add_argument('-i','--idonly', action='store_true',
                        help='set to only return scan id numbers')
    
    clargs = parser.parse_args()
    sess = NessusSession(clargs.NessusHost, clargs.AccessKey, clargs.SecretKey)

    resp = sess.get('scans', params={'folder_id': clargs.folder_id})
    dat = resp.json()
    scans = dat['scans']
    if clargs.idonly:
        out = sorted(((str(s['id']),) for s in scans),
                     reverse=clargs.descending)
    elif clargs.alphasort:
        out = sorted(((s['name'], str(s['id'])) for s in scans),
                     reverse=clargs.descending)
    else:
        out = sorted(((str(s['id']), s['name']) for s in scans),
                     reverse=clargs.descending)
    print('\n'.join('\t'.join(i) for i in out))
