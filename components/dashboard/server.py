#!/usr/bin/env python3
import http.server
import socketserver
import json
import subprocess
import os

PORT = 8080

class HealthHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/health':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            
            try:
                # Get health data from kubectl
                result = subprocess.run(
                    ['kubectl', 'get', 'icapservice', 'test-scanner', '-o', 'json'],
                    capture_output=True, text=True
                )
                
                if result.returncode == 0:
                    data = json.loads(result.stdout)
                    status = data.get('status', {})
                    
                    response = {
                        'overallScore': status.get('currentHealthScore', 0),
                        'readyReplicas': status.get('readyReplicas', 0),
                        'totalReplicas': data.get('spec', {}).get('replicas', 0),
                        'trafficPattern': 'normal',  # Would come from logs
                        'threatLevel': 'elevated',
                        'readiness': 95,
                        'latency': 90,
                        'signatures': 85,
                        'errors': 98,
                        'resources': 92,
                        'queue': 100
                    }
                    self.wfile.write(json.dumps(response).encode())
                else:
                    self.wfile.write(json.dumps({'error': 'Not found'}).encode())
            except Exception as e:
                self.wfile.write(json.dumps({'error': str(e)}).encode())
        else:
            super().do_GET()

os.chdir('/home/sen/capslock-operator/dashboard')
with socketserver.TCPServer(("", PORT), HealthHandler) as httpd:
    print(f"Dashboard running at http://localhost:{PORT}")
    print("Press Ctrl+C to stop")
    httpd.serve_forever()
