#!/usr/bin/python3
from itertools import chain
import re

from nessus_session import NessusScanSession, nessus_scan_script_arg_parse

def get_high_risk(
        sess,
        severity,
        include_unsupported=False,
        include_ssl=False,
        only_public=False):
    params = {}
    if only_public:
        params = {
            'filter.0.quality': 'eq',
            'filter.0.filter': 'exploit_available',
            'filter.0.value': 'true',
            'filter.search_type': 'and',
            'includeHostDetailsForHostDiscovery': 'true'
        }

    resp = sess.get('', params=params)
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
            if ('ssl' not in k.lower() and 'tls' not in k.lower())
        }
                   
    return {k: sess.plugin_hosts(v) for k, v in plugins.items()}


if __name__=='__main__':
    parser = nessus_scan_script_arg_parse('Find critical vulnerabilities in a given nessus scan')
    parser.add_argument('-s', '--severity', type=int, default=4, help='severity to find. 4: Critical, 3: High....')
    parser.add_argument('-nc', '--num_col', type=int, default=3, help='number of columns for output')
    parser.add_argument('--include_unsupported', action='store_true', help='set to include unsupported findings')
    parser.add_argument('--include_ssl', action='store_true', help='set to include weak TLS/SSL findings')
    parser.add_argument('--only_public', action='store_true', help='set to only include findings with public exploits')
    parser.add_argument('--filter_description', nargs='?', help='regex to match for display')
    clargs = parser.parse_args()

    sess = NessusScanSession(clargs.scan_no, clargs.NessusHost, clargs.AccessKey, clargs.SecretKey, history_id=clargs.history_id)
    scan = get_high_risk(sess, clargs.severity, clargs.include_unsupported, clargs.include_ssl, clargs.only_public)

    # set up the regex to filter descriptions with
    key_reg = clargs.filter_description
    if key_reg is not None:
        key_reg = re.compile(key_reg)

    for key, hosts in scan.items():
        if key_reg is not None:
            if key_reg.search(key) is None:
                continue
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


