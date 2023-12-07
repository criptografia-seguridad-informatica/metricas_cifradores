from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding


class CifradorAsimetrico:
    def __init__(self):
        # Generate a key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = private_key.public_key()
        self.private_key = private_key

    def get_public_key(self):
        # Serialize and return the public key
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def encriptar(self, numero_a_encriptar):
        # Convert the number to bytes
        number_bytes = str(numero_a_encriptar).encode('utf-8')

        # Encrypt the bytes using the public key
        encrypted_data = self.public_key.encrypt(
            number_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return encrypted_data

    def desencriptar(self, numero_a_desencriptar):
        # Decrypt the data using the private key
        decrypted_data = self.private_key.decrypt(
            numero_a_desencriptar,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Convert the decrypted bytes back to a number
        decrypted_number = float(decrypted_data.decode('utf-8'))

        return decrypted_number
