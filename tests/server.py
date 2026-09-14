from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import gzip, json, sys

class H(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def log_message(self, *a): pass
    def sendb(self, code, body=b'', headers=None):
        self.send_response(code)
        if headers:
            for k,v in headers.items(): self.send_header(k,v)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        if self.command != 'HEAD': self.wfile.write(body)
    def do_GET(self):
        if self.path == '/plain': self.sendb(200,b'hello frog\n',{'Content-Type':'text/plain','X-Test':'yes'})
        elif self.path == '/redirect': self.send_response(302); self.send_header('Location','/plain'); self.send_header('Content-Length','8'); self.end_headers(); self.wfile.write(b'redirect')
        elif self.path == '/gzip':
            b=gzip.compress(b'compressed frog\n')
            self.sendb(200,b,{'Content-Encoding':'gzip','Content-Type':'text/plain'})
        elif self.path == '/chunked':
            self.send_response(200); self.send_header('Transfer-Encoding','chunked'); self.end_headers()
            for x in (b'hello ',b'chunked ',b'frog\n'):
                self.wfile.write(f'{len(x):x}\r\n'.encode()+x+b'\r\n')
            self.wfile.write(b'0\r\nX-Trailer: ok\r\n\r\n')
        elif self.path == '/auth':
            if self.headers.get('Authorization') == 'Basic dXNlcjpwYXNz': self.sendb(200,b'auth ok\n')
            else: self.sendb(401,b'no\n')
        elif self.path == '/404': self.sendb(404,b'nope\n')
        else: self.sendb(200, self.path.encode()+b'\n')
    def do_HEAD(self): self.do_GET()
    def body(self):
        n=self.headers.get('Content-Length')
        if n is not None: return self.rfile.read(int(n))
        if self.headers.get('Transfer-Encoding','').lower()=='chunked':
            out=b''
            while True:
                line=self.rfile.readline().split(b';',1)[0].strip(); n=int(line,16)
                if not n:
                    self.rfile.readline(); break
                out += self.rfile.read(n); self.rfile.read(2)
            return out
        return b''
    def echo(self):
        b=self.body()
        obj={'method':self.command,'body':b.decode('latin1'),'x':self.headers.get('X-Frog'),'host':self.headers.get('Host')}
        data=json.dumps(obj).encode()
        self.sendb(200,data,{'Content-Type':'application/json'})
    do_POST=echo; do_PUT=echo; do_PATCH=echo; do_DELETE=echo

port=int(sys.argv[1]) if len(sys.argv)>1 else 18080
ThreadingHTTPServer(('127.0.0.1',port),H).serve_forever()
