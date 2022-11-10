#!/usr/bin/python3
import json
import sys

from nessus_session import NessusScanSession, nessus_scan_script_arg_parse


def getversion_108797(output):
    ver = next(s for s in output['plugin_output'].split('\n') if s.strip().startswith('Microsoft Windows'))
    return ver 

def getversion_33850(output):
    ver = next(s for s in output['plugin_output'].split('\n') if s.strip().startswith('FreeBSD'))
    ver = ' '.join(ver.split(' ')[:2])
    return ver 

def getversion_default(output):
    verdict = dict(map(lambda x: x.strip(), s.split(':', 1)) for s in output['plugin_output'].strip().split('\n') if ':' in s)
    for verlab in ('Version', 'Reported version', 'Installed version', 'Product'):
        ver = verdict.get(verlab, None)
        if ver is not None:
            return ver


getversiondict = {108797: getversion_108797, 33850: getversion_33850}

if __name__=='__main__':
    parser = nessus_scan_script_arg_parse('Return the plugin output from a given nessus scan')
    parser.add_argument('plugin_id', nargs="?", default=None, type=int, help='plugin number')
    parser.add_argument('--hosts', action='store_true', help='set to return a list of affected hosts')
    parser.add_argument('--hostports', action='store_true', help='set to return a list of affected hosts')
    parser.add_argument('--version', action='store_true', help='set to return a list of hosts and the version in the output')
    parser.add_argument('--list_plugins', action='store_true', help='set to list known plugins for standard software')
    parser.add_argument('--raw_output', action='store_true', help='set to print the raw plugin output')

    


    clargs = parser.parse_args()
    if clargs.list_plugins:
        pluginlist = {
            'Apache': 48204,
            'Apache Tomcat': 39446,
            'Apache Log4j': 156000,
            'Acme thttp': 97145,
            'PHP': 48243,
            'OpenSSL': 57323,
            'MSSQL': 10144,
            'Windows OS': 108797,
        }
        print('\n'.join('\t'.join(map(str, i)) for i in pluginlist.items()))
        sys.exit()
        

    sess = NessusScanSession(clargs.scan_no, clargs.NessusHost, clargs.AccessKey, clargs.SecretKey, history_id=clargs.history_id)
    if clargs.hosts:
        print(
            '\n'.join(
                sorted(sess.plugin_hosts(clargs.plugin_id),
                       key=lambda s: tuple(map(int, s.split('.'))))
            )
        )
        sys.exit()
    resp = sess.get('/plugins/{}'.format(clargs.plugin_id))
    data = resp.json()
    if data['outputs'] is None:
        sys.exit()
    if clargs.version:
        getversion = getversiondict.get(clargs.plugin_id, getversion_default)

        for output in data['outputs']:
            version = getversion(output)
            print(version)
            for port, out in output['ports'].items():
                port = port.split('/')[0].strip()
                for host in out:
                    print(f'{host["hostname"]}:{port}')

    if clargs.raw_output:
        for output in data['outputs']:
            print(output['plugin_output'])
            for port, out in output['ports'].items():
                port = port.split('/')[0].strip()
                for host in out:
                    print(f'{host["hostname"]}:{port}')
            

                
                
                
