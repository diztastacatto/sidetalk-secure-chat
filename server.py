import socket
import threading
import json
import os
import time
import base64
import hashlib
import hmac
import uuid
import datetime
import bcrypt
from datetime import timedelta
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import constant_time
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import paramiko
from cryptography import x509
from cryptography.x509.oid import NameOID

# Copyright (c) 2023 Golam Mahadi Rafi
# Sidetalk Secure Chat Application
# All rights reserved.
# Unauthorized copying of this file, via any medium is strictly prohibited.

class SidetalkServer:
    def __init__(self, host='0.0.0.0', port=9999, sftp_port=2222):
        self.host = host
        self.port = port
        self.sftp_port = sftp_port
        self.app_name = "Sidetalk"
        self.author = "Golam Mahadi Rafi"
        self.version = "1.0.0"
        self.clients = {}
        self.running = False
        self.clients_lock = threading.Lock()
        self.auth_attempts = {}  # Track failed auth attempts
        
        # Load user credentials
        self.users = self._load_users()
        
        # Load or generate server certificate for authentication
        self._setup_server_certificate()
    
    def _load_users(self):
        """Load user credentials from users.json file"""
        users = {}
        try:
            with open('users.json', 'r') as f:
                users_data = json.load(f)
                for username, password_hash in users_data.items():
                    users[username] = password_hash
            print(f"Loaded {len(users)} user(s) from users.json")
        except FileNotFoundError:
            print("users.json not found. Creating default admin user...")
            # Create default admin user
            default_password = "password"
            hashed_password = bcrypt.hashpw(default_password.encode('utf-8'), bcrypt.gensalt())
            users = {'admin': hashed_password.decode('utf-8')}
            
            # Save to file
            with open('users.json', 'w') as f:
                json.dump(users, f, indent=4)
            print("Created default admin user with password 'password'")
        except Exception as e:
            print(f"Error loading users: {e}")
            # Fallback to default admin
            default_password = "password"
            hashed_password = bcrypt.hashpw(default_password.encode('utf-8'), bcrypt.gensalt())
            users = {'admin': hashed_password.decode('utf-8')}
        
        return users
    
    def _setup_server_certificate(self):
        """Generate or load server certificate for authentication"""
        cert_path = "server_cert.pem"
        key_path = "server_key.pem"
        
        if os.path.exists(cert_path) and os.path.exists(key_path):
            # Load existing certificate
            with open(cert_path, "rb") as f:
                cert_data = f.read()
            with open(key_path, "rb") as f:
                key_data = f.read()
        else:
            # Generate self-signed certificate with RSA key
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            
            # Create certificate
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.COMMON_NAME, self.host),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, f"{self.app_name} by {self.author}"),
            ])
            
            # Fix the datetime deprecation warnings
            now = datetime.datetime.now(datetime.timezone.utc)
            
            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                private_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                now
            ).not_valid_after(
                now + datetime.timedelta(days=365)
            ).add_extension(
                x509.SubjectAlternativeName([x509.DNSName(self.host)]),
                critical=False,
            ).sign(private_key, hashes.SHA256())
            
            # Save certificate and key
            with open(cert_path, "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))
            with open(key_path, "wb") as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
    
    def display_banner(self):
        """Display the application banner with author information"""
        banner = f"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║                            {self.app_name} Secure Chat                          ║
║                                                                              ║
║                           Version: {self.version}                              ║
║                                                                              ║
║                           Made by: {self.author}                              ║
║                                                                              ║
║                   Copyright (c) 2023 {self.author}. All rights reserved.      ║
║                                                                              ║
║                   Unauthorized copying, distribution or modification           ║
║                   of this software is strictly prohibited.                    ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
        """
        print(banner)
    
    def get_author_signature(self):
        """Return author signature as proof of ownership"""
        return {
            "app_name": self.app_name,
            "author": self.author,
            "signature": hashlib.sha256(f"{self.app_name}{self.author}".encode()).hexdigest(),
            "copyright": f"Copyright (c) 2023 {self.author}"
        }
    
    def start(self):
        self.display_banner()
        self.running = True
        
        # Start chat server
        chat_thread = threading.Thread(target=self._start_chat_server)
        chat_thread.daemon = True
        chat_thread.start()
        
        # Start SFTP server
        sftp_thread = threading.Thread(target=self._start_sftp_server)
        sftp_thread.daemon = True
        sftp_thread.start()
        
        print(f"\n{self.app_name} server started successfully!")
        print(f"Chat server listening on {self.host}:{self.port}")
        print(f"SFTP server listening on {self.host}:{self.sftp_port}")
        print(f"Author: {self.author}")
        print(f"Loaded {len(self.users)} user(s)")
        
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()
    
    def stop(self):
        self.running = False
        with self.clients_lock:
            for client_id, client_info in self.clients.items():
                try:
                    client_info['socket'].close()
                except:
                    pass
        print(f"\n{self.app_name} server stopped.")
    
    def _start_chat_server(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((self.host, self.port))
        server_socket.listen(5)
        
        print(f"Chat server listening on {self.host}:{self.port}")
        
        while self.running:
            try:
                client_socket, address = server_socket.accept()
                print(f"\nNew connection from {address}")
                
                # Generate a unique session ID for this client
                session_id = str(uuid.uuid4())
                
                # Send session ID and app info to client
                initial_data = {
                    'session_id': session_id,
                    'app_info': self.get_author_signature()
                }
                
                try:
                    initial_data_json = json.dumps(initial_data).encode('utf-8')
                    client_socket.send(initial_data_json)
                    print(f"Sent initial data to client: {initial_data}")
                except Exception as e:
                    print(f"Error sending initial data: {e}")
                    client_socket.close()
                    continue
                
                # Store client info
                client_id = f"{address[0]}:{address[1]}"
                with self.clients_lock:
                    self.clients[client_id] = {
                        'socket': client_socket,
                        'address': address,
                        'session_id': session_id,
                        'authenticated': False,
                        'last_activity': time.time()
                    }
                
                # Start client handler thread
                client_thread = threading.Thread(
                    target=self._handle_client,
                    args=(client_id,)
                )
                client_thread.daemon = True
                client_thread.start()
                
            except Exception as e:
                print(f"Error accepting connection: {e}")
    
    def _handle_client(self, client_id):
        client_info = None
        with self.clients_lock:
            client_info = self.clients.get(client_id)
        
        if not client_info:
            return
            
        client_socket = client_info['socket']
        address = client_info['address']
        
        try:
            print(f"Handling client {client_id}...")
            while self.running:
                # Check if client is still in the list
                with self.clients_lock:
                    if client_id not in self.clients:
                        break
                
                # Receive message
                try:
                    print(f"Waiting for message from {client_id}...")
                    data = client_socket.recv(4096)
                    if not data:
                        print(f"No data received from {client_id}, closing connection.")
                        break
                    
                    print(f"Received {len(data)} bytes from {client_id}")
                    
                    # Update last activity
                    with self.clients_lock:
                        self.clients[client_id]['last_activity'] = time.time()
                    
                    # Parse message
                    try:
                        message = json.loads(data.decode('utf-8'))
                        msg_type = message.get('type')
                        
                        print(f"Received message type: {msg_type} from {client_id}")
                        
                        if msg_type == 'auth':
                            # Handle authentication
                            username = message.get('username')
                            password = message.get('password')
                            client_ip = address[0]
                            
                            print(f"Authentication request from {username} at {client_ip}")
                            
                            # Check for too many auth attempts
                            if client_ip in self.auth_attempts:
                                if self.auth_attempts[client_ip]['count'] >= 5:
                                    if time.time() - self.auth_attempts[client_ip]['last_attempt'] < 300:  # 5 minutes
                                        # Send auth failure
                                        response = {
                                            'type': 'auth_response',
                                            'success': False,
                                            'message': 'Too many authentication attempts. Try again later.'
                                        }
                                        self._send_json_response(client_socket, response)
                                        continue
                                    else:
                                        # Reset counter
                                        self.auth_attempts[client_ip] = {
                                            'count': 1,
                                            'last_attempt': time.time()
                                        }
                            else:
                                self.auth_attempts[client_ip] = {
                                    'count': 1,
                                    'last_attempt': time.time()
                                }
                            
                            # Check credentials against stored users
                            if username in self.users:
                                stored_hash = self.users[username].encode('utf-8')
                                if bcrypt.checkpw(password.encode('utf-8'), stored_hash):
                                    with self.clients_lock:
                                        self.clients[client_id]['authenticated'] = True
                                        self.clients[client_id]['username'] = username
                                    
                                    print(f"Authentication successful for {username}")
                                    
                                    # Send auth success
                                    response = {
                                        'type': 'auth_response',
                                        'success': True,
                                        'message': 'Authentication successful',
                                        'app_info': self.get_author_signature()
                                    }
                                else:
                                    # Increment auth attempt counter
                                    self.auth_attempts[client_ip]['count'] += 1
                                    
                                    print(f"Authentication failed for {username} - wrong password")
                                    
                                    # Send auth failure
                                    response = {
                                        'type': 'auth_response',
                                        'success': False,
                                        'message': 'Authentication failed'
                                    }
                            else:
                                # Increment auth attempt counter
                                self.auth_attempts[client_ip]['count'] += 1
                                
                                print(f"Authentication failed for {username} - user not found")
                                
                                # Send auth failure
                                response = {
                                    'type': 'auth_response',
                                    'success': False,
                                    'message': 'Authentication failed'
                                }
                            
                            # Send response
                            print(f"Sending authentication response: {response}")
                            self._send_json_response(client_socket, response)
                        
                        elif msg_type == 'message':
                            # Handle chat message
                            with self.clients_lock:
                                if not self.clients[client_id]['authenticated']:
                                    continue
                                
                                message_text = message.get('message')
                                username = self.clients[client_id].get('username', client_id)
                            
                            print(f"\n[{username}]: {message_text}")
                            
                            # Create message to broadcast to all clients
                            broadcast_msg = {
                                'type': 'message',
                                'sender': username,
                                'message': message_text,
                                'timestamp': time.time(),
                                'app_info': self.get_author_signature()
                            }
                            
                            # Broadcast to all clients (including the sender)
                            self._broadcast_to_all_clients(broadcast_msg)
                        
                        elif msg_type == 'file_request':
                            # Handle file transfer request
                            filename = message.get('filename')
                            file_size = message.get('size')
                            
                            with self.clients_lock:
                                if not self.clients[client_id]['authenticated']:
                                    continue
                                
                                username = self.clients[client_id].get('username', client_id)
                            
                            print(f"\nFile transfer request from {username}: {filename} ({file_size} bytes)")
                            
                            # Send file transfer info to SFTP server
                            file_info = {
                                'type': 'file_info',
                                'filename': filename,
                                'size': file_size,
                                'client': client_id,
                                'timestamp': time.time(),
                                'app_info': self.get_author_signature()
                            }
                            
                            self._broadcast_to_all_clients(file_info)
                    
                    except json.JSONDecodeError:
                        print(f"Invalid JSON received from {client_id}")
                    except Exception as e:
                        print(f"Error processing message from {client_id}: {e}")
                
                except socket.timeout:
                    print(f"Socket timeout for {client_id}")
                    break
                except ConnectionResetError:
                    print(f"Connection reset by {client_id}")
                    break
                except Exception as e:
                    print(f"Error receiving data from {client_id}: {e}")
                    break
                    
        except Exception as e:
            print(f"Error handling client {client_id}: {e}")
        finally:
            with self.clients_lock:
                if client_id in self.clients:
                    del self.clients[client_id]
            try:
                client_socket.close()
            except:
                pass
            print(f"Client {client_id} disconnected")
    
    def _send_json_response(self, socket, response):
        """Send JSON response to client"""
        try:
            message_json = json.dumps(response).encode('utf-8')
            print(f"Sending response: {message_json}")
            socket.send(message_json)
            print("Response sent successfully")
            return True
        except Exception as e:
            print(f"Error sending response: {e}")
            return False
    
    def _broadcast_to_all_clients(self, message):
        """Broadcast a message to all connected clients"""
        message_json = json.dumps(message).encode('utf-8')
        
        clients_to_send = []
        with self.clients_lock:
            for client_id, client_info in self.clients.items():
                clients_to_send.append((client_id, client_info))
        
        print(f"Broadcasting message to {len(clients_to_send)} clients")
        
        for client_id, client_info in clients_to_send:
            try:
                client_info['socket'].send(message_json)
                print(f"Message sent to client {client_id}")
                
            except Exception as e:
                print(f"Error broadcasting to {client_id}: {e}")
    
    def _start_sftp_server(self):
        # Create SSH server for SFTP
        host_key = paramiko.RSAKey.generate(2048)
        
        class SidetalkSSHServer(paramiko.ServerInterface):
            def __init__(self, chat_server):
                self.chat_server = chat_server
                self.event = threading.Event()
                
            def check_auth_password(self, username, password):
                # Simple authentication (in real app, use proper auth system)
                if username == 'sftp' and password == 'sftppassword':
                    return paramiko.AUTH_SUCCESSFUL
                return paramiko.AUTH_FAILED
                
            def check_auth_publickey(self, username, key):
                # Public key authentication could be implemented here
                return paramiko.AUTH_FAILED
                
            def get_allowed_auths(self, username):
                return 'password,publickey'
                
            def check_channel_request(self, kind, chanid):
                if kind == 'session':
                    return paramiko.OPEN_SUCCEEDED
                return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
                
            def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
                return False
                
            def check_channel_shell_request(self, channel):
                self.event.set()
                return True
        
        try:
            # Create socket for SFTP server
            sftp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sftp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sftp_socket.bind((self.host, self.sftp_port))
            sftp_socket.listen(5)
            
            print(f"SFTP server listening on {self.host}:{self.sftp_port}")
            
            while self.running:
                try:
                    client_socket, address = sftp_socket.accept()
                    print(f"\nNew SFTP connection from {address}")
                    
                    # Create transport
                    transport = paramiko.Transport(client_socket)
                    transport.add_server_key(host_key)
                    
                    # Create SSH server
                    ssh_server = SidetalkSSHServer(self)
                    transport.start_server(server=ssh_server)
                    
                    # Create SFTP channel
                    channel = transport.accept()
                    if channel is not None:
                        # Create SFTP server
                        sftp_server = paramiko.SFTPServer(channel)
                        print(f"SFTP session started for {address}")
                        
                        # Store SFTP client info
                        client_id = f"sftp:{address[0]}:{address[1]}"
                        with self.clients_lock:
                            self.clients[client_id] = {
                                'socket': client_socket,
                                'address': address,
                                'transport': transport,
                                'channel': channel,
                                'sftp_server': sftp_server,
                                'authenticated': True,
                                'is_sftp': True,
                                'last_activity': time.time()
                            }
                        
                except Exception as e:
                    print(f"Error with SFTP connection: {e}")
                    
        except Exception as e:
            print(f"Error starting SFTP server: {e}")

if __name__ == "__main__":
    # Create upload and download directories if they don't exist
    os.makedirs('upload', exist_ok=True)
    os.makedirs('download', exist_ok=True)
    
    server = SidetalkServer()
    server.start()
