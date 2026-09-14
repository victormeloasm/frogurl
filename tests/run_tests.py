#!/usr/bin/env python3
import gzip
import json
import os
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

EXE = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else './frogurl')

class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def log_message(self, *args): pass
    def sendb(self, code, body=b'', headers=None):
        self.send_response(code)
        for k, v in (headers or {}).items(): self.send_header(k, v)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        if self.command != 'HEAD': self.wfile.write(body)
    def read_body(self):
        if self.headers.get('Transfer-Encoding', '').lower() == 'chunked':
            out = bytearray()
            while True:
                n = int(self.rfile.readline().strip().split(b';', 1)[0], 16)
                if not n:
                    while self.rfile.readline() not in (b'\r\n', b'\n', b''): pass
                    return bytes(out)
                out += self.rfile.read(n)
                assert self.rfile.read(2) == b'\r\n'
        n = int(self.headers.get('Content-Length', '0'))
        return self.rfile.read(n)
    def do_GET(self):
        if self.path == '/plain': return self.sendb(200, b'hello frog\n', {'Content-Type':'text/plain'})
        if self.path == '/redirect':
            self.send_response(302); self.send_header('Location', '/plain'); self.send_header('Content-Length', '0'); self.end_headers(); return
        if self.path == '/gzip': return self.sendb(200, gzip.compress(b'compressed frog\n'), {'Content-Encoding':'gzip'})
        if self.path == '/chunked':
            self.send_response(200); self.send_header('Transfer-Encoding', 'chunked'); self.end_headers()
            for x in (b'hello ', b'chunked ', b'frog\n'):
                self.wfile.write(f'{len(x):x}\r\n'.encode() + x + b'\r\n')
            self.wfile.write(b'0\r\n\r\n'); return
        if self.path == '/404': return self.sendb(404, b'nope\n')
        if self.path == '/auth': return self.sendb(200, (self.headers.get('Authorization') or '').encode())
        return self.sendb(404)
    def do_HEAD(self): return self.do_GET()
    def echo(self):
        b = self.read_body()
        out = json.dumps({'method':self.command, 'body':b.decode('latin1')}).encode()
        return self.sendb(200, out, {'Content-Type':'application/json'})
    do_POST = echo
    do_PUT = echo
    do_PATCH = echo
    do_DELETE = echo

def run(*args, stdin=None):
    return subprocess.run([EXE, *args], input=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

def must(cond, msg):
    if not cond: raise AssertionError(msg)

srv = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
port = srv.server_address[1]
threading.Thread(target=srv.serve_forever, daemon=True).start()
base = f'http://127.0.0.1:{port}'
try:
    c = run(base + '/plain'); must(c.returncode == 0 and c.stdout == b'hello frog\n', 'plain GET')
    c = run('-L', base + '/redirect'); must(c.returncode == 0 and c.stdout == b'hello frog\n', 'redirect')
    c = run('--compressed', base + '/gzip'); must(c.returncode == 0 and c.stdout == b'compressed frog\n', 'gzip')
    c = run(base + '/chunked'); must(c.returncode == 0 and c.stdout == b'hello chunked frog\n', 'chunked')
    c = run('-u', 'a:', base + '/auth'); must(c.returncode == 0 and c.stdout == b'Basic YTo=', 'basic auth')
    c = run('-d', 'abc=123', base + '/echo'); must(json.loads(c.stdout) == {'method':'POST','body':'abc=123'}, 'POST data')
    c = run('--data-binary', '@-', '-X', 'POST', base + '/echo', stdin=b'frog stdin')
    must(json.loads(c.stdout) == {'method':'POST','body':'frog stdin'}, 'chunked stdin upload')
    c = run('-I', base + '/plain'); must(c.returncode == 0 and b'HTTP/1.1 200' in c.stdout, 'HEAD')
    c = run('--status', base + '/plain'); must(c.stdout == b'200\n', '--status')
    c = run('-f', base + '/404'); must(c.returncode == 22 and c.stdout == b'', '-f')
    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, 'out')
        c = run('-o', path, base + '/plain')
        must(c.returncode == 0 and open(path, 'rb').read() == b'hello frog\n', '-o')
        c = run('-#', '-o', path, base + '/plain')
        must(c.returncode == 0 and b'100%' in c.stderr, '-# progress bar')
    print('frogurl tests: OK')
finally:
    srv.shutdown()
