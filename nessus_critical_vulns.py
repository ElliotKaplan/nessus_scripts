#!/usr/bin/python3
from itertools import chain

from nessus_session import NessusSession, nessus_script_arg_parse

def get_high_risk(
        sess,
        scan_number,
        severity,
        include_unsupported=False,
        include_ssl=False):
    resp = sess.get('/scans/{}'.format(scan_number))
    dat = resp.json()
    # get the plugins reporting the desired severity level
    plugins = {
        v['plugin_name']: v['plugin_id']
        for v in dat['vulnerabilities']
        if v['severity'] == severity
    }
    if not include_unsupported:
        plugins = {
            k: v
            for k, v in plugins.items()
            if 'unsupported' not in k.lower()
        }
    if not include_ssl:
        plugins = {
            k: v
            for k, v in plugins.items()
            if 'ssl' not in k.lower()
        }
                   
    return {k: sess.plugin_hosts(scan_number, v) for k, v in plugins.items()}


if __name__=='__main__':
    parser = nessus_script_arg_parse('Find critical vulnerabilities in a given nessus scan')
    parser.add_argument('-s', '--severity', type=int, default=4, help='severity to find. 4: Critical, 3: High....')
    parser.add_argument('-nc', '--num_col', type=int, default=3, help='number of columns for output')
    parser.add_argument('--include_unsupported', action='store_true', help='set to include unsupported findings')
    parser.add_argument('--include_ssl', action='store_true', help='set to include weak TLS/SSL findings')
    clargs = parser.parse_args()

    sess = NessusSession(clargs.NessusHost, clargs.ApiKey, clargs.SecretKey)
    scan = get_high_risk(sess, clargs.scan_no, clargs.severity, clargs.include_unsupported, clargs.include_ssl)
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


