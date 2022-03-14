from itertools import chain

from nessus_session import NessusSession, nessus_script_arg_parse

def get_unsupported(sess, scan_number):
    resp = sess.get('/scans/{}'.format(scan_number))
    dat = resp.json()
    # find results labeled 'unsupported'
    unsup = {
        d['plugin_name']: d['plugin_id']
        for d in dat['vulnerabilities']
        if 'unsupported' in d['plugin_name'].lower()
    }
    out = dict()
    for key, ind in unsup.items():
        resp = sess.get('/scans/{}/plugins/{}'.format(scan_number, ind))
        dat = resp.json()
        hosts = set()
        for port in dat['outputs'][0]['ports'].values():
            hosts = hosts.union({h['hostname'] for h in port})
        out[key] = hosts
    return out
        
if __name__=='__main__':
    parser = nessus_script_arg_parse('Find outdated operating systems/software in a given nessus scan')
    parser.add_argument('-nc', '--num_col', type=int, default=3, help='number of columns for output')
    clargs = parser.parse_args()

    sess = NessusSession(clargs.NessusHost, clargs.ApiKey, clargs.SecretKey)
    scan = get_unsupported(sess, clargs.scan_no)
    for key, hosts in scan.items():
        print(key)
        width = max(map(len, hosts)) + 5
        fmtstr = ('{:<' + str(width) + 's}')*clargs.num_col
        hosts = sorted(hosts, key=lambda h: list(map(int, h.split('.'))))
        nrow = len(hosts)//clargs.num_col + 1
        cols = [hosts[i*nrow:(i+1)*nrow] for i in range(clargs.num_col)]
        while len(cols[-1]) != len(cols[0]):
            cols[-1].append('')
        print('\n'.join(fmtstr.format(*r) for r in zip(*cols)))
        
        print('='*32)


