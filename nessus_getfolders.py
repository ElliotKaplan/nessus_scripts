#!/usr/bin/python3
import json

from nessus_session import NessusSession, nessus_script_arg_parse
if __name__=='__main__':
    parser = nessus_script_arg_parse('Find outdated operating systems/software in a given nessus scan')
    parser.add_argument('-d', '--descending', action='store_true',
                        help='set to sort output by count descending')
    parser.add_argument('-a', '--alphasort', action='store_true',
                        help='set to sort output alphabetially')
    parser.add_argument('-i','--idonly', action='store_true',
                        help='set to only return folder id numbers')
    clargs = parser.parse_args()
    sess = NessusSession(clargs.NessusHost, clargs.AccessKey, clargs.SecretKey)

    resp = sess.get('folders')
    dat = resp.json()
    folders = dat['folders']
    if clargs.idonly:
        out = sorted(((str(f['id']),) for f in folders),
                     reverse=clargs.descending)
    elif clargs.alphasort:
        out = sorted(((f['name'], str(f['id'])) for f in folders),
                     reverse=clargs.descending)
    else:
        out = sorted(((str(f['id']), f['name']) for f in folders),
                     reverse=clargs.descending)
    print('\n'.join('\t'.join(i) for i in out))
        
