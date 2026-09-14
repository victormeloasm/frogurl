#!/usr/bin/env python3
"""Local protocol/security regressions. Python stdlib + the openssl CLI only."""
import contextlib
import gzip
import json
import os
from pathlib import Path
import select
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import zlib

EXE = os.path.abspath(sys.argv.pop(1) if len(sys.argv) > 1 else './frogurl')


def run(*args, data=None, cwd=None, timeout=6):
    p = subprocess.run([EXE, '--connect-timeout', '1', '--timeout', '0.5', *args],
                       input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       cwd=cwd, timeout=timeout)
    if b'AddressSanitizer' in p.stderr or b'runtime error:' in p.stderr or b'LeakSanitizer' in p.stderr:
        raise AssertionError(p.stderr.decode(errors='replace'))
    return p


def request(sock):
    data = b''
    while b'\r\n\r\n' not in data:
        x = sock.recv(4096)
        if not x:
            return data
        data += x
        if len(data) > 131072:
            raise AssertionError('oversize request')
    return data


def response(body=b'frog', headers=b'', code=b'200 OK'):
    return b'HTTP/1.1 ' + code + b'\r\nContent-Length: ' + str(len(body)).encode() + b'\r\n' + headers + b'\r\n' + body


class Server:
    def __init__(self, handler, family=socket.AF_INET):
        self.listener = socket.socket(family)
        self.listener.bind(('::1' if family == socket.AF_INET6 else '127.0.0.1', 0))
        self.listener.listen(8)
        self.listener.settimeout(.1)
        self.port = self.listener.getsockname()[1]
        self.handler = handler
        self.errors = []
        self.stopping = threading.Event()
        self.clients = []
        self.threads = []
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self):
        while not self.stopping.is_set():
            try:
                sock, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            sock.settimeout(2)
            self.clients.append(sock)
            t = threading.Thread(target=self.handle, args=(sock,), daemon=True)
            self.threads.append(t)
            t.start()

    def handle(self, sock):
        try:
            with sock:
                self.handler(sock)
        except (BrokenPipeError, ConnectionResetError, socket.timeout, ssl.SSLError):
            pass  # Several adversarial cases intentionally close mid-exchange.
        except Exception as e:
            self.errors.append(e)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.stopping.set()
        self.listener.close()
        self.thread.join(1)
        for sock in self.clients:
            with contextlib.suppress(OSError):
                sock.shutdown(socket.SHUT_RDWR)
        for t in self.threads:
            t.join(1)
        if not args[0] and self.errors:
            raise self.errors[0]

    def http(self, path='/'):
        return f'http://127.0.0.1:{self.port}{path}'


def raw_server(payload):
    def handle(sock):
        request(sock)
        sock.sendall(payload)
    return Server(handle)


class FTP(Server):
    def __init__(self, payload=b'frog\x00\xff\r\n' * 10000, **config):
        self.payload = payload
        self.config = config
        self.commands = []
        self.uploaded = b''
        family = config.get('family', socket.AF_INET)
        super().__init__(self.session, family)

    def url(self, path='/file.bin'):
        host = '[::1]' if self.config.get('family') == socket.AF_INET6 else '127.0.0.1'
        return f'ftp://{host}:{self.port}{path}'

    def session(self, control):
        cfg = self.config
        control.sendall(cfg.get('greeting', b'220-Test FTP\r\nSome multiline text\r\n220 Ready\r\n'))
        reader = control.makefile('rb')
        data_listener = None
        try:
            while True:
                line = reader.readline(8194)
                if not line:
                    break
                self.commands.append(line)
                cmd, _, arg = line.rstrip(b'\r\n').partition(b' ')
                if cmd == b'USER':
                    control.sendall(b'230 Logged in\r\n' if cfg.get('user_only') else b'331 Password required\r\n')
                elif cmd == b'PASS':
                    control.sendall(cfg.get('login', b'230 Logged in\r\n'))
                elif cmd == b'TYPE':
                    control.sendall(b'200 Binary\r\n')
                elif cmd == b'CWD':
                    control.sendall(cfg.get('cwd_reply', b'250 Directory changed\r\n'))
                elif cmd == b'SIZE':
                    control.sendall(cfg.get('size', b'213 ' + str(len(self.payload)).encode() + b'\r\n'))
                elif cmd in (b'EPSV', b'PASV'):
                    if cmd == b'EPSV' and cfg.get('pasv'):
                        control.sendall(b'500 EPSV unsupported\r\n')
                        continue
                    if 'passive_reply' in cfg:
                        control.sendall(cfg['passive_reply'])
                        continue
                    data_listener = socket.socket(control.family)
                    data_listener.bind(('::1' if control.family == socket.AF_INET6 else '127.0.0.1', 0))
                    data_listener.listen(1)
                    data_listener.settimeout(2)
                    port = data_listener.getsockname()[1]
                    if cmd == b'EPSV':
                        d = cfg.get('delimiter', '|')
                        reply = f'229 Entering ({d}{d}{d}{port}{d})\r\n'
                    else:
                        reply = f'227 Entering (203,0,113,99,{port // 256},{port % 256})\r\n'
                    control.sendall(reply.encode())
                elif cmd in (b'RETR', b'STOR'):
                    if cfg.get('reject_transfer'):
                        control.sendall(b'550 File unavailable\r\n')
                        break
                    control.sendall(cfg.get('preliminary', b'150 Opening data\r\n'))
                    ds, _ = data_listener.accept()
                    with ds:
                        ds.settimeout(2)
                        if cmd == b'RETR':
                            ds.sendall(self.payload)
                        else:
                            while True:
                                x = ds.recv(16384)
                                if not x:
                                    break
                                self.uploaded += x
                    control.sendall(cfg.get('final', b'226 Complete\r\n'))
                else:
                    control.sendall(b'500 Unknown command\r\n')
        finally:
            reader.close()
            if data_listener:
                data_listener.close()


class ProtocolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.cert = str(Path(cls.tmp.name) / 'cert.pem')
        cls.key = str(Path(cls.tmp.name) / 'key.pem')
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2',
                        '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1',
                        '-keyout', cls.key, '-out', cls.cert], check=True, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL)
        cls.tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        cls.tls.load_cert_chain(cls.cert, cls.key)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def ok(self, p):
        self.assertEqual(p.returncode, 0, p.stderr)

    def bad(self, p):
        self.assertGreater(p.returncode, 0, p.stderr)

    def test_ftp_download_and_metadata(self):
        with FTP() as s:
            p = run(s.url()); self.ok(p); self.assertEqual(p.stdout, s.payload)
            self.assertIn(b'USER anonymous\r\n', s.commands)
        with FTP() as s:
            p = run('--json-meta', s.url()); self.ok(p)
            meta = json.loads(p.stdout)
            self.assertEqual(meta['status'], 226)
            self.assertEqual(meta['body_bytes'], len(s.payload))

    def test_ftp_auth_and_redaction(self):
        with FTP() as s:
            p = run('-v', '-u', 'frog:top-secret', s.url()); self.ok(p)
            self.assertIn(b'PASS top-secret\r\n', s.commands)
            self.assertNotIn(b'top-secret', p.stderr)
        with FTP(login=b'530 Invalid password\r\n') as s:
            self.bad(run('-u', 'frog:bad', s.url()))
            self.assertFalse(any(c.startswith(b'RETR') for c in s.commands))
        with FTP(user_only=True) as s:
            self.ok(run('-u', 'frog:', s.url()))
            self.assertFalse(any(c.startswith(b'PASS') for c in s.commands))

    def test_ftp_upload_file_and_stdin(self):
        payload = bytes(range(256)) * 500
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'payload.bin'; path.write_bytes(payload)
            with FTP() as s:
                p = run('-#', '-T', str(path), s.url()); self.ok(p)
                self.assertEqual(s.uploaded, payload); self.assertIn(b'100%', p.stderr)
        with FTP() as s:
            self.ok(run('-T', '-', s.url(), data=payload)); self.assertEqual(s.uploaded, payload)
        with FTP() as s:
            self.ok(run('-T', '-', s.url(), data=b'')); self.assertEqual(s.uploaded, b'')

    def test_ftp_pasv_pins_peer(self):
        with FTP(pasv=True) as s:
            p = run(s.url()); self.ok(p); self.assertEqual(p.stdout, s.payload)
            self.assertIn(b'PASV\r\n', s.commands)  # Advertised address 203.0.113.99 must be ignored.

    def test_ftp_ipv6(self):
        try:
            srv = FTP(family=socket.AF_INET6)
        except OSError:
            self.skipTest('IPv6 loopback unavailable')
        with srv as s:
            p = run(s.url()); self.ok(p); self.assertEqual(p.stdout, s.payload)

    def test_ftp_paths_and_names(self):
        with tempfile.TemporaryDirectory() as td, FTP() as s:
            p = run('-O', s.url('/dir%20one/nested/file%20two.bin'), cwd=td); self.ok(p)
            self.assertEqual((Path(td) / 'file two.bin').read_bytes(), s.payload)
            self.assertIn(b'CWD dir one\r\n', s.commands)
            self.assertIn(b'CWD nested\r\n', s.commands)
            self.assertIn(b'RETR file two.bin\r\n', s.commands)
        for path, expected in [('//tmp/file', b'CWD /\r\n'), ('/%2Ftmp/file;type=i', b'CWD /tmp\r\n')]:
            with self.subTest(path=path), FTP() as s:
                self.ok(run(s.url(path))); self.assertIn(expected, s.commands)

    def test_ftp_no_size_and_empty(self):
        with FTP(size=b'502 No SIZE\r\n') as s:
            p = run(s.url()); self.ok(p); self.assertEqual(p.stdout, s.payload)
        with FTP(payload=b'') as s:
            p = run(s.url()); self.ok(p); self.assertEqual(p.stdout, b'')

    def test_ftp_output_and_metadata(self):
        with tempfile.TemporaryDirectory() as td, FTP() as s:
            path = Path(td) / 'file'
            p = run('--json-meta', '-o', str(path), s.url()); self.ok(p)
            self.assertEqual(path.read_bytes(), s.payload)
            self.assertEqual(json.loads(p.stdout)['body_bytes'], len(s.payload))

    def test_ftp_rejects_injection(self):
        for path in ['/x%0d%0aDELE%20file', '/x%00evil', '/x%ffevil', '/dir%0A/file', '/x%0', '/x%GG']:
            with self.subTest(path=path), FTP() as s:
                self.bad(run(s.url(path))); self.assertEqual(s.commands, [])
        with FTP() as s:
            self.bad(run('-u', 'frog:pass\r\nDELE file', s.url())); self.assertEqual(s.commands, [])

    def test_ftp_rejects_bad_names_and_options(self):
        for path in ['/', '/..', '/.', '/dir/', '/f;type=a', '/f?query', '/dir//file']:
            with self.subTest(path=path), FTP() as s:
                self.bad(run(s.url(path))); self.assertEqual(s.commands, [])
        for args in [('-k',), ('--compressed',), ('-X', 'DELE'), ('-d', 'data'), ('-x', 'http://127.0.0.1'), ('-I',), ('-L',)]:
            with self.subTest(args=args), FTP() as s:
                self.bad(run(*args, s.url())); self.assertEqual(s.commands, [])
        with FTP() as s:
            self.bad(run('-O', s.url('/..%2Fvictim'))); self.assertEqual(s.commands, [])

    def test_ftp_bad_passive_ports(self):
        replies = [b'229 Missing\r\n', b'229 (|||0|)\r\n', b'229 (|||65536|)\r\n',
                   b'229 (|||999999999999999999999999|)\r\n', b'229 (|||-1|)\r\n',
                   b'229 (|||42!x)\r\n', b'229 (|)\r\n', b'229 (|||12|\r\n']
        for reply in replies:
            with self.subTest(reply=reply), FTP(passive_reply=reply) as s:
                self.bad(run(s.url())); self.assertFalse(any(c.startswith(b'RETR') for c in s.commands))
        for reply in [b'227 (1,2,3,4,99999999999999,1)\r\n', b'227 (1,2,3,4,0,0)\r\n', b'227 (1,2,3,4,1)\r\n']:
            with self.subTest(reply=reply), FTP(pasv=True, passive_reply=reply) as s:
                self.bad(run(s.url()))
        with FTP(delimiter='!') as s:
            self.ok(run(s.url()))

    def test_ftp_bad_size_and_completion(self):
        for size in [b'213 \r\n', b'213 -1\r\n', b'213 99999999999999999999999999\r\n', b'213 12junk\r\n', b'213 1\r\n', b'213 999999\r\n']:
            with self.subTest(size=size), FTP(size=size) as s:
                self.bad(run(s.url()))
        with FTP(final=b'426 Transfer failed\r\n') as s:
            self.bad(run(s.url()))
        with FTP(final=b'250 Complete\r\n') as s:
            self.ok(run(s.url()))
        with FTP(reject_transfer=True) as s:
            self.bad(run(s.url()))

    def test_ftp_reply_bounds(self):
        greetings = [b'220 Ready\x00hidden\r\n', b'220 ' + b'x' * 9000 + b'\r\n',
                     b'220-Start\r\n' + (b' padding\r\n' * 8000), b'220-partial\r\n', b'999 Invalid\r\n']
        for greeting in greetings:
            with self.subTest(size=len(greeting)), FTP(greeting=greeting) as s:
                self.bad(run(s.url()))
        with FTP(greeting=b'120 Wait\r\n220 Ready\r\n') as s:
            self.ok(run(s.url()))

    def test_http_long_reason_no_stack_disclosure(self):
        payload = response(b'', code=b'200 ' + b'R' * 2000)
        with raw_server(payload) as s:
            p = run('-I', s.http()); self.ok(p); self.assertEqual(p.stdout, payload)

    def test_http_header_injection(self):
        for args in [('-H', 'X-Test: value\r\nInjected: yes'), ('-H', 'X Bad: value'),
                     ('-A', 'agent\r\nInjected: yes'), ('-X', 'GET\r\nInjected: yes')]:
            with self.subTest(args=args):
                self.bad(run(*args, 'http://127.0.0.1:1/'))

    def test_http_framing_rejection(self):
        bad = [b'Content-Length: 4junk\r\n', b'Content-Length: -1\r\n', b'Content-Length: +4\r\n',
               b'Content-Length: 999999999999999999999999\r\n', b'Content-Length: 4\r\nContent-Length: 4\r\n',
               b'Content-Length: 4\r\nTransfer-Encoding: chunked\r\n', b'Transfer-Encoding: gzip, chunked\r\n',
               b'Transfer-Encoding: chunked, gzip\r\n', b'Bad Header: value\r\n', b'X: a\x00b\r\n',
               b'No-colon\r\n', b' Content-Length: 4\r\n']
        for headers in bad:
            with self.subTest(headers=headers), raw_server(b'HTTP/1.1 200 OK\r\n' + headers + b'\r\nfrog') as s:
                self.bad(run(s.http()))
        for code in [b'2000 Bad', b'-200 Bad', b'200x Bad', b'999999999999999999999999 Bad', b'101 Switching']:
            with self.subTest(code=code), raw_server(response(code=code)) as s:
                self.bad(run(s.http()))

    def test_http_request_framing(self):
        for args in [('-d', 'frog', '-H', 'Content-Length: 2'), ('-d', 'frog', '-H', 'Content-Length: 4', '-H', 'Transfer-Encoding: chunked'),
                     ('-d', 'frog', '-H', 'Transfer-Encoding: identity'), ('--data-binary', '@-', '-H', 'Content-Length: 4')]:
            with self.subTest(args=args), raw_server(response()) as s:
                self.bad(run(*args, s.http(), data=b'frog'))

    def test_http_compression_integrity(self):
        plain = b'compressible frog\n' * 10000
        good = gzip.compress(plain)
        for body in [good[:-5], good[:-1], good[:-1] + bytes([good[-1] ^ 1]), good + b'garbage', good + gzip.compress(b'x')[:-3]]:
            with self.subTest(size=len(body)), raw_server(response(body, b'Content-Encoding: gzip\r\n')) as s:
                self.bad(run('--compressed', s.http()))
        for body, encoding, expected in [(good, b'gzip', plain), (good + gzip.compress(b'end'), b'gzip', plain + b'end'),
                                         (zlib.compress(plain), b'deflate', plain)]:
            with self.subTest(encoding=encoding, size=len(body)), raw_server(response(body, b'Content-Encoding: ' + encoding + b'\r\n')) as s:
                p = run('--compressed', s.http()); self.ok(p); self.assertEqual(p.stdout, expected)
        with raw_server(response(zlib.compress(plain)[:-2], b'Content-Encoding: deflate\r\n')) as s:
            self.bad(run('--compressed', s.http()))

    def test_http_bad_chunks_and_trailers(self):
        chunks = [b'-0\r\n\r\n', b'+4\r\nfrog\r\n0\r\n\r\n', b'0x4\r\nfrog\r\n0\r\n\r\n',
                  b'4\r\nfr', b'4\r\nfrogXX', b'0\r\n' + b'X: v\r\n' * 12000 + b'\r\n',
                  b'0\r\nContent-Length: 1\r\n\r\n', b'0\r\ninvalid\r\n\r\n']
        for chunk in chunks:
            with self.subTest(size=len(chunk)), raw_server(b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n' + chunk) as s:
                self.bad(run(s.http()))
        with raw_server(b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4;foo=bar\r\nfrog\r\n0\r\nX: y\r\n\r\n') as s:
            p = run(s.http()); self.ok(p); self.assertEqual(p.stdout, b'frog')

    def test_http_interim_and_header_bounds(self):
        with raw_server(b'HTTP/1.1 100 Continue\r\n\r\n' * 20 + response()) as s:
            self.bad(run(s.http()))
        with raw_server(b'HTTP/1.1 200 OK\r\n' + b'X: y\r\n' * 1100 + b'\r\n') as s:
            self.bad(run(s.http()))
        with raw_server(b'HTTP/1.1 100 Continue\r\n\r\n' + response()) as s:
            p = run(s.http()); self.ok(p); self.assertEqual(p.stdout, b'frog')

    def test_http_truncated_length(self):
        with raw_server(b'HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nfrog') as s:
            self.bad(run(s.http()))

    def test_http_cross_origin_credentials(self):
        seen = []
        def target(sock):
            seen.append(request(sock)); sock.sendall(response())
        with Server(target) as dest:
            with raw_server(response(b'', b'Location: ' + dest.http().encode() + b'\r\n', b'302 Found')) as source:
                self.ok(run('-L', '-u', 'frog:secret', '-H', 'Authorization: Bearer abc', '-H', 'Cookie: secret=1', '-H', 'Host: old.example', source.http()))
        self.assertNotIn(b'Authorization:', seen[0]); self.assertNotIn(b'Cookie:', seen[0]); self.assertNotIn(b'old.example', seen[0])
        self.assertIn(b'Host: 127.0.0.1:', seen[0])

    def test_http_remote_name_not_redirect_controlled(self):
        with tempfile.TemporaryDirectory() as td:
            victim = Path(td) / 'victim'; victim.write_bytes(b'KEEP')
            with raw_server(response()) as dest, raw_server(response(b'', b'Location: ' + dest.http('/victim').encode() + b'\r\n', b'302 Found')) as source:
                self.ok(run('-LO', source.http('/wanted'), cwd=td))
            self.assertEqual(victim.read_bytes(), b'KEEP')
            self.assertEqual((Path(td) / 'wanted').read_bytes(), b'frog')

    def test_http_redirect_path_semantics(self):
        for location, expected in [('/a//b', b'/a//b'), ('/a/.', b'/a/'), ('/a/b/..', b'/a/'),
                                   ('../c?x=1', b'/c?x=1'), ('?new=1', b'/a/start?new=1')]:
            seen = []
            def handle(sock):
                req = request(sock); seen.append(req)
                if len(seen) == 1:
                    sock.sendall(response(b'', b'Location: ' + location.encode() + b'\r\n', b'302 Found'))
                else:
                    sock.sendall(response())
            with self.subTest(location=location), Server(handle) as server:
                self.ok(run('-L', server.http('/a/start?old=1')))
            self.assertEqual(seen[-1].split(b' ')[1], expected)

    def test_http_proxy_credentials_not_origin(self):
        seen = []
        def target(sock):
            seen.append(request(sock)); sock.sendall(response())
        with Server(target) as s:
            self.ok(run('-H', 'Proxy-Authorization: secret', s.http()))
        self.assertNotIn(b'Proxy-Authorization', seen[0])

    def test_http_redirect_body_headers(self):
        seen = []
        def target(sock):
            seen.append(request(sock)); sock.sendall(response())
        with Server(target) as dest, raw_server(response(b'', b'Location: ' + dest.http().encode() + b'\r\n', b'303 See Other')) as source:
            self.ok(run('-L', '-d', 'frog', '-H', 'Content-Length: 4', '-H', 'Content-Type: text/plain', source.http()))
        self.assertTrue(seen[0].startswith(b'GET ')); self.assertNotIn(b'Content-Length:', seen[0]); self.assertNotIn(b'Content-Type:', seen[0])

    def test_http_redirect_no_ftp(self):
        with FTP() as dest, raw_server(response(b'', b'Location: ' + dest.url().encode() + b'\r\n', b'302 Found')) as source:
            self.bad(run('-L', '-u', 'frog:secret', source.http())); self.assertEqual(dest.commands, [])

    def test_http_redirect_stdin_replay_rejected(self):
        for code in [b'301 Found', b'302 Found', b'307 Temporary', b'308 Permanent']:
            with self.subTest(code=code), raw_server(response(b'', b'Location: /again\r\n', code)) as s:
                p = run('-L', '-T', '-', s.http(), data=b'frog'); self.bad(p)
                self.assertIn(b'cannot replay stdin', p.stderr)

    def test_http_metadata_file(self):
        with tempfile.TemporaryDirectory() as td, raw_server(response()) as s:
            path = Path(td) / 'out'
            p = run('--json-meta', '-o', str(path), s.http()); self.ok(p)
            self.assertEqual(path.read_bytes(), b'frog'); self.assertEqual(json.loads(p.stdout)['body_bytes'], 4)

    def test_remote_name_symlink_and_hardlink(self):
        with tempfile.TemporaryDirectory() as td:
            victim = Path(td) / 'victim'; victim.write_bytes(b'KEEP')
            output = Path(td) / 'file.bin'
            for kind in ['symlink', 'hardlink']:
                if kind == 'symlink': output.symlink_to(victim)
                else: os.link(victim, output)
                with self.subTest(kind=kind), raw_server(response()) as s:
                    self.bad(run('-O', s.http('/file.bin'), cwd=td))
                self.assertEqual(victim.read_bytes(), b'KEEP')
                with FTP() as s:
                    self.bad(run('-O', s.url(), cwd=td))
                self.assertEqual(victim.read_bytes(), b'KEEP'); output.unlink()

    def test_numeric_options_and_bad_urls(self):
        for option in ['--timeout', '--connect-timeout']:
            for value in ['nan', 'NaN', 'inf', '-1', '99999999999999999999999']:
                with self.subTest(option=option, value=value):
                    self.bad(run(option, value, 'http://127.0.0.1:1/'))
        for url in ['http://127.0.0.1:0/', 'http://127.0.0.1:65536/', 'http://127.0.0.1:99999999999999999/',
                    'http://[not-ip]/', 'http://::1/', 'http://host%0d%0a/', 'http://u:p@host/', 'http://host\\evil/']:
            with self.subTest(url=url): self.assertEqual(run(url).returncode, 3)
        self.bad(run('--max-redirs', '', 'http://127.0.0.1:1/'))

    def tls_handler(self, sock):
        with self.tls.wrap_socket(sock, server_side=True) as secure:
            request(secure); secure.sendall(response())

    def test_https_certificate_validation(self):
        with Server(self.tls_handler) as s:
            url = f'https://127.0.0.1:{s.port}/'
            self.bad(run(url))
            p = run('--cacert', self.cert, url); self.ok(p); self.assertEqual(p.stdout, b'frog')
            self.ok(run('-k', url))

    def test_https_hostname_mismatch(self):
        # Send the same local server through CONNECT under a different TLS hostname.
        def proxy(sock):
            request(sock); sock.sendall(b'HTTP/1.1 200 OK\r\n\r\n'); self.tls_handler(sock)
        with Server(proxy) as s:
            p = run('--cacert', self.cert, '-x', s.http(), 'https://wrong.invalid/')
            self.bad(p); self.assertIn(b'TLS', p.stderr)

    def test_https_connect_default_port(self):
        seen = []
        def proxy(sock):
            seen.append(request(sock)); sock.sendall(b'HTTP/1.1 200 OK\r\n\r\n'); self.tls_handler(sock)
        with Server(proxy) as s:
            self.ok(run('--cacert', self.cert, '-x', s.http(), 'https://localhost/'))
        self.assertTrue(seen[0].startswith(b'CONNECT localhost:443 HTTP/1.1\r\n'), seen[0])
        self.assertIn(b'Host: localhost:443\r\n', seen[0])

    def test_tls_handshake_and_read_timeout(self):
        def stalled(sock):
            time.sleep(1.2)
        start = time.monotonic()
        with Server(stalled) as s:
            self.bad(run('-k', f'https://127.0.0.1:{s.port}/', timeout=3))
        self.assertLess(time.monotonic() - start, 3)
        def stalled_body(sock):
            with self.tls.wrap_socket(sock, server_side=True) as secure:
                request(secure); secure.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n')
                time.sleep(1.2)
        with Server(stalled_body) as s:
            self.bad(run('--cacert', self.cert, f'https://127.0.0.1:{s.port}/', timeout=3))

    def test_tls_write_timeout(self):
        def no_read(sock):
            with self.tls.wrap_socket(sock, server_side=True):
                time.sleep(1.4)
        with Server(no_read) as s:
            self.bad(run('-k', '-T', '-', f'https://127.0.0.1:{s.port}/', data=b'x' * 16000000, timeout=4))

    def test_tls_unclean_eof(self):
        def truncated(sock):
            secure = self.tls.wrap_socket(sock, server_side=True)
            request(secure); secure.sendall(b'HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nfrog')
            fd = secure.detach(); os.close(fd)  # No TLS close_notify.
        with Server(truncated) as s:
            self.bad(run('-k', f'https://127.0.0.1:{s.port}/'))

    def test_proxy_bounds(self):
        with raw_server(b'HTTP/1.1 200 OK\r\n' + b'X: a\r\n' * 12000 + b'\r\n') as s:
            self.bad(run('-k', '-x', s.http(), 'https://localhost/'))

    def test_output_failure(self):
        if not Path('/dev/full').exists(): self.skipTest('/dev/full unavailable')
        with raw_server(response()) as s:
            self.bad(run('-o', '/dev/full', s.http()))
        with FTP() as s:
            self.bad(run('-o', '/dev/full', s.url()))


if __name__ == '__main__':
    unittest.main(verbosity=2)
