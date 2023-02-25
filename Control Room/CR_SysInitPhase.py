from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

private_key = ec.generate_private_key(ec.SECP256K1())
public_key = private_key.public_key()
public_numbers = public_key.public_numbers()
q = (1 << 256) - (1 << 32) - 977

serialized_private = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

serialized_public = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

with open('../Public/CR_public.pem', 'wb') as f:
    f.write(serialized_public)

with open('CR_public.pem', 'wb') as f:
    f.write(serialized_public)

with open('CR_private.pem', 'wb') as f:
    f.write(serialized_private)