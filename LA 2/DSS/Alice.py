from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature
import hashlib
import base64
import json
import socket
from datetime import datetime

class SignatureClient:
    def __init__(self, host='localhost', port=5555):
        self.host = host
        self.port = port
        self.private_key = None
        self.public_key = None
        self.server_public_key = None
        
    def generate_keys(self):
        """Generate RSA key pair for client"""
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        
        # Print client's keys
        private_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()
        
        public_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        
        print("\nClient's Private Key:")
        print(private_pem)
        print("\nClient's Public Key:")
        print(public_pem)
        
        return public_pem

    def sign_message(self, message):
        """Sign a message with client's private key"""
        message_struct = {
            "sender": "Alice",
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
        """Verify a message using server's public key"""
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
            self.server_public_key.verify(
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

    def send_message(self, message):
        """Send a signed message to server"""
        try:
            # Create socket connection
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect((self.host, self.port))
            
            # Exchange public keys if not done yet
            if not self.server_public_key:
                # Send client's public key
                public_pem = self.generate_keys()
                client_socket.send(public_pem.encode())
                
                # Receive server's public key
                server_pem = client_socket.recv(4096).decode()
                self.server_public_key = serialization.load_pem_public_key(
                    server_pem.encode(),
                    backend=default_backend()
                )
                print("\nPublic key exchange completed")
            
            # Sign and send message
            message_package = self.sign_message(message)
            print("\nSending message package:")
            print(json.dumps(message_package, indent=2))
            client_socket.send(json.dumps(message_package).encode())
            
            # Receive and verify response
            response_data = client_socket.recv(4096).decode()
            response_package = json.loads(response_data)
            print("\nReceived response package:")
            print(json.dumps(response_package, indent=2))
            
            is_valid, result = self.verify_message(response_package)
            print("\nResponse verification result:")
            print(f"Valid: {is_valid}")
            if is_valid:
                print("Response content:", result["content"])
            else:
                print("Verification failed:", result)
            
            client_socket.close()
            
        except Exception as e:
            print(f"Error: {str(e)}")

if __name__ == "__main__":
    client = SignatureClient()
    while True:
        message = input("\nEnter message to send (or 'quit' to exit): ")
        if message.lower() == 'quit':
            break
        client.send_message(message)