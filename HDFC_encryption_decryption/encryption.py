import os
import json
import base64
import hashlib
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from Crypto.PublicKey import RSA
from jwt import encode, decode
def generate_alphanumeric_bytes(length):
    return ''.join([chr(os.urandom(1)[0] % 36 + 48 + (7 if c > 9 else 0)) for c in os.urandom(length)]).encode()
    
# Load RSA keys and certificate
with open("HDFC_priv.key", "rb") as priv_key_file:
    private_key = serialization.load_pem_private_key(priv_key_file.read(), password=b"city123", backend=default_backend())
with open("HDFC_PUB.cer", "rb") as cert_file:
    certificate = x509.load_pem_x509_certificate(cert_file.read(), default_backend())
    public_key = certificate.public_key()
with open("api_hdfcbank_com.cer", "rb") as c_file:
    certificate = x509.load_pem_x509_certificate(c_file.read(), default_backend())
    public_key = certificate.public_key()
print('public_key is ', public_key)
public_key_data = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtUlK8MdCzJb5ROqmfW6B
/KnXsAhWaHM8JNV3XmY0yyzZw4QsQKaqGoAvujKSwQeS1Uq+uJGcRXvmoWrMlqWA
cLeGxswGCCVptS/gu2JP/hQ+r3bo7Xv9Jb4KdVQN7IGJUt9BZ4lb9tWRjgseSTNx
sicFUpVj68Xw+ZWYZXdhARm3TtkhYmNKuMstVe9rA7dTQdAj9D/MJFZ7r+axC9n0
uj6M6I2QdS5EoV+Bvoerb669duen6dvgFBRJSp93dO0WpotJT+z9oeCbJEUIxgK/
Td/mjUWgD0+DbR8KIkZ9OLCB2rFXH0UzkLCEpooWeGW7ZA8nmsU7/eQrPBcx3EdU
xwIDAQAB
-----END PUBLIC KEY-----"""
public_key = serialization.load_pem_public_key(
    public_key_data.encode(),
    backend=default_backend()
)


# Prepare payload
payload = {
    "fetchbalancerequest": {
        "header": {
            "ReqId": "C23492837592",
            "EnqDtTm": "2024-11-22 09:47:42",
            "ClientCode": "CITY",
            "UserId": "CITYAPI",
            "Password": "ne8Gssc6C8Q81i8vIjt9vfjuI8jpFvftOJfbXx9uaQM=3qmQePuSs2pLvAmPXDStVBKL5s+IGagF1OupDvcyV3wnJkSuAeWdzTvBrmDyL1vPv8fnH7G2ZbroenTskAi/qc5aDSDjMrPgUq46cdFjly72rrSe5/LoDsylbOBH",
            "ReservedFieldH1": "THE CORPORATE USER WHICH IS SENDING THE REQUEST CAN SEND THE HEADER DATA UP TO 100 ALPHANUMERIC DATA"
        },
        "details": {
            "ReservedFieldD1": "THE CORPORATE USER WHICH IS REQUESTING FOR FETCH BALANCE SERVICE CAN SEND UPTO 200 ALPHANUMERIC DETAILS IN THIS FEILD WHICH IS RESERVED IN THE API FOR CAPTURING THE OTHER DETAILS REGARDING THE REQUEST"
        }
    }
}

# JWT encoding
header = {"typ": "JWT", "alg": "RS256"}
encoded_jwt = encode(payload, private_key, algorithm="RS256", headers=header).encode()

# Generate alphanumeric symmetric key and IV
symmetric_key = generate_alphanumeric_bytes(32)
iv = generate_alphanumeric_bytes(16)

# Encrypt the symmetric key
encrypted_key = public_key.encrypt(symmetric_key, padding.PKCS1v15())

# Encrypt JWT using AES in CBC mode
cipher = Cipher(algorithms.AES(symmetric_key), modes.CBC(iv), backend=default_backend())
encryptor = cipher.encryptor()
padder = PKCS7(128).padder()
padded_data = padder.update(encoded_jwt) + padder.finalize()
encrypted_jwt = encryptor.update(padded_data) + encryptor.finalize()

# Base64 encode the encrypted values
symmetric_key_encrypted_value = base64.b64encode(encrypted_key).decode()
request_signature_encrypted_value = base64.b64encode(iv + encrypted_jwt).decode()

# Output results as JSON
output = {
    "RequestSignatureEncryptedValue": request_signature_encrypted_value,
    "SymmetricKeyEncryptedValue": symmetric_key_encrypted_value,
    "Scope": "CITY",
    "TransactionId": "19112024120715237425",
    "OAuthTokenValue": "KSSgaV3cXASLGddKZqfaCsUZcc3T",
    "Id-token-jwt": ""
}
print(json.dumps(output, indent=4))
