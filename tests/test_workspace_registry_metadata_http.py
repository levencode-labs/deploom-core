"""Real HTTP state transitions; no public registry or package-manager execution."""
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from dependency_live_roadmap_generator import DeadlineClock, LiveDataClient
from workspace_registry_metadata import fetch_workspace_packuments


class MetadataHTTPTests(unittest.TestCase):
    def test_cookie_and_no_store_replay_match_sequential_across_five_names(self):
        for stateful in ('cookie', 'no-store'):
            with self.subTest(stateful=stateful):
                seen = []
                class Handler(BaseHTTPRequestHandler):
                    def do_GET(self):
                        cookie = self.headers.get('Cookie', '')
                        seen.append((self.path, cookie))
                        name = self.path.strip('/')
                        body = json.dumps({'name': name, 'view': 'B' if 'view=B' in cookie else 'A',
                            'versions': {'1.0.0': {'name': name, 'version': '1.0.0'}}}).encode()
                        self.send_response(200)
                        if self.path == '/p0':
                            self.send_header('Set-Cookie' if stateful == 'cookie' else 'Cache-Control',
                                             'view=B; Path=/' if stateful == 'cookie' else 'no-store')
                        self.send_header('Content-Length', str(len(body)))
                        self.end_headers()
                        self.wfile.write(body)
                    def log_message(self, *args):
                        pass
                server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                clients = []
                try:
                    def client():
                        value = LiveDataClient(f'http://127.0.0.1:{server.server_port}',
                            timeout=1, batch_size=8, sleep_sec=0, allow_registry_metadata_redirects=False)
                        value.set_deadline(DeadlineClock(10))
                        clients.append(value)
                        return value
                    names = ['p'+str(i) for i in range(5)]
                    actual = fetch_workspace_packuments(client(), names)
                    speculative = list(seen)
                    reference = client()
                    expected = {name: reference.fetch_npm_metadata(name) for name in names}
                    self.assertEqual(actual, expected)
                    self.assertEqual(len(speculative), 9)
                    fifth = [cookie for path, cookie in speculative if path == '/p4']
                    self.assertEqual(fifth, ['view=B' if stateful == 'cookie' else ''])
                finally:
                    for value in clients:
                        value.session.close()
                    server.shutdown();server.server_close();thread.join(3)
