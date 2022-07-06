#!/usr/bin/python3
from itertools import chain
import json
import re
import sys

from nessus_session import NessusScanSession, nessus_scan_script_arg_parse

def get_version(sess, severity):
    # get the plugin outputs where there is a less than sign
    version_reg = re.compile('\d+(\.[x\d]+)+')
    params = {
        'filter.0.quality': 'match',
        'filter.0.filter': 'plugin_name',
        'filter.0.value': '<',
        'filter.search_type': 'and',
        'includeHostDetailsForHostDiscovery': 'true'
    }
    resp = sess.get('', params=params)
    dat = resp.json()
    plugins = {
        v['plugin_name']: v['plugin_id']
        for v in dat['vulnerabilities']
        if v['severity_index'] >= severity
    }
    for name, p_id in plugins.items():
        print(name)
        print(sess.plugin_hosts(p_id))
        resp = sess.get('/plugins/{}'.format(p_id))
        plugin = resp.json()
        software = version_reg.split(name)[0].split('<')[0].split('>')[0].strip()
        versiondata = list()
        for output in plugin['outputs']:
            plugout = output['plugin_output']
            if plugout is None:
                continue
            plugout = [s.strip() for s in plugout.split('\n')]
            try:
                version = next(s
                               for s in plugout
                               if (
                                       s.startswith('Installed version')
                                       or s.startswith('Reported version')
                               )).split(':')[1].strip()
            except StopIteration:
                continue
            for port, hosts in output['ports'].items():
                versiondata += [(name, h['hostname'], ' '.join((software, version))) for h in hosts]
        return versiondata
        
        


if __name__=='__main__':
    parser = nessus_scan_script_arg_parse('Find outdated operating systems/software in a given nessus scan')
    parser.add_argument('-s', '--severity', type=int, default=1, help='min severity to find. 4: Critical, 3: High....')
    parser.add_argument('--software_first', action='store_true', help='set to print software before hostname')
    parser.add_argument('--sep', default='\t', help='separator between columns in output')
                        
    clargs = parser.parse_args()

    sess = NessusScanSession(clargs.scan_no, clargs.NessusHost, clargs.AccessKey, clargs.SecretKey)
    versiondata = get_version(sess, clargs.severity)
    if versiondata is None:
        sys.exit()
    if clargs.software_first:
        print('\n'.join(clargs.sep.join((v[2], v[1])) for v in versiondata))
    else:
        print('\n'.join(clargs.sep.join(v) for v in versiondata))
    
