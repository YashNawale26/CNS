from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature
import hashlib
import base64
import json
import socket
from datetime import datetime 

class SignatureServer:
    def __init__(self, host='localhost', port=5555):
        self.host = host
        self.port = port
        self.private_key = None
        self.public_key = None
        self.client_public_key = None
        self.socket = None
        
    def generate_keys(self):
        """Generate RSA key pair for server"""
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        
        # Print server's keys
        private_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()
        
        public_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        
        print("\nServer's Private Key:")
        print(private_pem)
        print("\nServer's Public Key:")
        print(public_pem)
        
        return public_pem

    def sign_message(self, message):
        """Sign a message with server's private key"""
        message_struct = {
            "sender": "Server",
            "timestamp": datetime.now().isoformat(),
            "content": message
        }
        message_bytes = json.dumps(message_struct).encode()
        
        # Calculate hash
        message_hash = hashlib.sha256(message_bytes).digest()
        
        # Sign the hash
        signature = self.private_key.sign(
            message_hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        return {
            "message": message_struct,
            "signature": base64.b64encode(signature).decode(),
            "hash": message_hash.hex()
        }

    def verify_message(self, message_package):
        """Verify a message using client's public key"""
        try:
            # Reconstruct message bytes
            message_bytes = json.dumps(message_package["message"]).encode()
            
            # Verify hash
            calculated_hash = hashlib.sha256(message_bytes).digest()
            if calculated_hash.hex() != message_package["hash"]:
                return False, "Hash mismatch"
            
            # Decode signature
            signature = base64.b64decode(message_package["signature"])
            
            # Verify signature
            self.client_public_key.verify(
                signature,
                calculated_hash,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            return True, message_package["message"]
            
        except InvalidSignature:
            return False, "Invalid signature"
        except Exception as e:
            return False, f"Verification error: {str(e)}"

    def start(self):
        """Start the server"""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind((self.host, self.port))
        self.socket.listen(1)
        print(f"\nServer listening on {self.host}:{self.port}")
        
        while True:
            try:
                # Accept client connection
                client_socket, address = self.socket.accept()
                print(f"\nClient connected from {address}")
                
                # Exchange public keys
                if not self.client_public_key:
                    # Send server's public key
                    public_pem = self.generate_keys()
                    client_socket.send(public_pem.encode())
                    
                    # Receive client's public key
                    client_pem = client_socket.recv(4096).decode()
                    self.client_public_key = serialization.load_pem_public_key(
                        client_pem.encode(),
                        backend=default_backend()
                    )
                    print("\nPublic key exchange completed")
                
                # Receive message from client
                data = client_socket.recv(4096).decode()
                if not data:
                    break
                
                message_package = json.loads(data)
                print("\nReceived message package:")
                print(json.dumps(message_package, indent=2))
                
                # Verify the message
                is_valid, result = self.verify_message(message_package)
                print("\nMessage verification result:")
                print(f"Valid: {is_valid}")
                if is_valid:
                    print("Message content:", result["content"])
                    
                    # Send response
                    response = self.sign_message(f"Message received and verified: {result['content']}")
                    client_socket.send(json.dumps(response).encode())
                else:
                    response = self.sign_message(f"Message verification failed: {result}")
                    client_socket.send(json.dumps(response).encode())
                
                client_socket.close()
                
            except Exception as e:
                print(f"Error: {str(e)}")
                break
        
        self.socket.close()

if __name__ == "__main__":
    server = SignatureServer()
    server.start() 