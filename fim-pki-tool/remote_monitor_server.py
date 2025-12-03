# remote_monitor_server.py — Secure Remote Monitoring Server
from flask import Flask, jsonify, request
from flask_cors import CORS
import ssl
import threading
from datetime import datetime
import json

class RemoteMonitorServer:
    """TLS-encrypted remote monitoring server"""
    
    def __init__(self, host='0.0.0.0', port=5443):
        self.host = host
        self.port = port
        self.app = Flask(__name__)
        CORS(self.app)
        
        self.events = []
        self.max_events = 1000
        self.is_running = False
        self.server_thread = None
        
        self._setup_routes()
    
    def _setup_routes(self):
        """Setup API routes"""
        
        @self.app.route('/api/status', methods=['GET'])
        def get_status():
            """Get server status"""
            return jsonify({
                "status": "online",
                "timestamp": datetime.now().isoformat(),
                "total_events": len(self.events)
            })
        
        @self.app.route('/api/events', methods=['GET'])
        def get_events():
            """Get recent events"""
            limit = request.args.get('limit', 50, type=int)
            return jsonify({
                "events": self.events[-limit:],
                "total": len(self.events)
            })
        
        @self.app.route('/api/events/latest', methods=['GET'])
        def get_latest_event():
            """Get latest event"""
            if self.events:
                return jsonify(self.events[-1])
            return jsonify({"message": "No events"})
        
        @self.app.route('/api/events', methods=['POST'])
        def add_event():
            """Add new event (internal use)"""
            data = request.get_json()
            if data:
                self.add_event(data)
                return jsonify({"success": True})
            return jsonify({"success": False, "error": "Invalid data"}), 400
        
        @self.app.route('/api/clear', methods=['POST'])
        def clear_events():
            """Clear all events"""
            self.events.clear()
            return jsonify({"success": True, "message": "Events cleared"})
    
    def add_event(self, event_data):
        """Add event to the log"""
        event = {
            "timestamp": datetime.now().isoformat(),
            "data": event_data
        }
        
        self.events.append(event)
        
        # Keep only recent events
        if len(self.events) > self.max_events:
            self.events = self.events[-self.max_events:]
    
    def start(self, use_ssl=False, cert_file=None, key_file=None):
        """Start the server"""
        if self.is_running:
            return False, "Server already running"
        
        def run_server():
            try:
                if use_ssl and cert_file and key_file:
                    # Create SSL context
                    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                    context.load_cert_chain(cert_file, key_file)
                    
                    self.app.run(
                        host=self.host,
                        port=self.port,
                        ssl_context=context,
                        threaded=True,
                        use_reloader=False
                    )
                else:
                    # Run without SSL (for testing)
                    self.app.run(
                        host=self.host,
                        port=self.port,
                        threaded=True,
                        use_reloader=False
                    )
            except Exception as e:
                print(f"Server error: {e}")
        
        self.server_thread = threading.Thread(target=run_server, daemon=True)
        self.server_thread.start()
        self.is_running = True
        
        protocol = "https" if use_ssl else "http"
        return True, f"Server started at {protocol}://{self.host}:{self.port}"
    
    def stop(self):
        """Stop the server"""
        # Note: Flask doesn't have a clean shutdown method
        # In production, you'd use a WSGI server like gunicorn
        self.is_running = False
        return True, "Server stopping..."
    
    def get_url(self, use_ssl=False):
        """Get server URL"""
        protocol = "https" if use_ssl else "http"
        return f"{protocol}://localhost:{self.port}"


# Utility function to generate self-signed certificate
def generate_self_signed_cert(cert_file="server.crt", key_file="server.key"):
    """Generate self-signed certificate for testing"""
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    from datetime import datetime, timedelta
    
    # Generate private key
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    # Write private key
    with open(key_file, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    # Generate certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "State"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "City"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureFIM"),
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ])
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName("localhost"),
            x509.DNSName("127.0.0.1"),
        ]),
        critical=False,
    ).sign(key, hashes.SHA256())
    
    # Write certificate
    with open(cert_file, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    
    return cert_file, key_file