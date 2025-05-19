from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# Generate private key
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

# Serialize private key to PEM format without encryption
pem_private = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()  # Add this line
)

# Write private key to a file
with open("private_key.pem", "wb") as f:
    f.write(pem_private)

# Generate public key
public_key = private_key.public_key()

# Serialize public key to PEM format
pem_public = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Write public key to a file
with open("public_key.pem", "wb") as f:
    f.write(pem_public)

print("Private and Public keys have been generated and saved.")
