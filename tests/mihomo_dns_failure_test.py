#!/usr/bin/env python3
"""Check the configured encrypted resolver fails closed in an isolated Mihomo.

No TUN, system proxy, user profile or policy selection is modified. The DNS-only
fixture uses a deliberately unavailable loopback proxy and forces real DNS
resolution rather than returning a fake-IP before querying upstream.
"""
import json
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import tempfile
import time
import yaml

ROOT=Path(__file__).resolve().parent.parent

def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0))
        return sock.getsockname()[1]


def main():
    binary=shutil.which('mihomo')
    if not binary:raise SystemExit('Mihomo is required for this native test')
    with tempfile.TemporaryDirectory(prefix='mihomo-dns-failure-') as tmp:
        path=Path(tmp);port=free_port()
        dns=yaml.safe_load((ROOT/'config/mihomo-runtime.yaml').read_text())['dns']
        dns['listen']='127.0.0.1:'+str(port);dns['enhanced-mode']='redir-host'
        shutil.copyfile(ROOT/'clash/PrivateLAN.list',path/'PrivateLAN.list')
        config={'mode':'rule','log-level':'error','allow-lan':False,'dns':dns,
            'proxies':[{'name':'UnavailableProxy','type':'http','server':'127.0.0.1','port':9}],
            'proxy-groups':[{'name':'Proxy','type':'select','proxies':['UnavailableProxy']}],
            'rule-providers':{'PrivateLAN':{'type':'file','behavior':'classical','format':'text','path':'./PrivateLAN.list'}},
            'rules':['MATCH,Proxy']}
        file=path/'config.yaml';file.write_text(yaml.safe_dump(config,sort_keys=False))
        with (path/'runtime.log').open('w') as output:
            process=subprocess.Popen([binary,'-d',str(path),'-f',str(file)],stdout=output,stderr=subprocess.STDOUT)
            try:
                deadline=time.monotonic()+8
                while True:
                    if process.poll() is not None:raise RuntimeError('isolated Mihomo failed to start')
                    try:
                        with socket.create_connection(('127.0.0.1',port),timeout=.3):break
                    except OSError:
                        if time.monotonic()>deadline:raise RuntimeError('DNS listener did not start')
                        time.sleep(.1)
                results=[]
                for qtype in (1,28):
                    name='routing-failure.example.net';encoded=b''.join(bytes([len(x)])+x.encode() for x in name.split('.'))+b'\x00'
                    message=struct.pack('!HHHHHH',1111,0x0100,1,0,0,0)+encoded+struct.pack('!HH',qtype,1)
                    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
                        sock.settimeout(8);sock.sendto(message,('127.0.0.1',port));data,_=sock.recvfrom(4096)
                    _,flags,_,answers,_,_=struct.unpack('!HHHHHH',data[:12]);rcode=flags&15
                    assert rcode==2 and answers==0,(qtype,rcode,answers)
                    results.append({'type':qtype,'rcode':rcode,'answers':answers})
                print(json.dumps({'status':'PASS','scope':'native encrypted-DNS failure without fallback','results':results}))
            finally:
                process.terminate()
                try:process.wait(timeout=5)
                except subprocess.TimeoutExpired:process.kill();process.wait()

if __name__=='__main__':main()
