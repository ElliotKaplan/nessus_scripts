from nessus_session import NessusSession, nessus_script_arg_parse

def get_synscan(sess, scan_number):
    resp = sess.get('/scans/{}/plugins/11219'.format(scan_number))
    dat = resp.json()
    out = list()
    for output in dat['outputs']:
        for port, arr in output['ports'].items():
            port = int(port.split()[0])
            if port == 21:
                out += ['ftp://{}'.format(h['hostname']) for h in arr]
            if port == 80:
                out += ['http://{}'.format(h['hostname']) for h in arr]
            if port == 443:
                out += ['https://{}'.format(h['hostname']) for h in arr]
            if port > 1000:
                out += ['http://{}:{}'.format(h['hostname'], port) for h in arr]
                out += ['https://{}:{}'.format(h['hostname'], port) for h in arr]
    return out

if __name__=='__main__':
    clargs = nessus_script_arg_parse('convert a syn scan to a file compatable with Eyewitness')
    clargs = parser.parse_args()
    
    sess = NessusSession(clargs.NessusHost, clargs.ApiKey, clargs.SecretKey)
    scan = get_synscan(sess, clargs.scan_no)
    print('\n'.join(scan))
    
