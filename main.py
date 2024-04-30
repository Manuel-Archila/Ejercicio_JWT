from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import jwt


# ========================================Parte 1========================================
# Generar un JWT firmado
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
).decode('utf-8')

public_key = private_key.public_key()
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode('utf-8')

payload = {
    "name": "John Doe",
    "admin": True,
    "message": "Hello, world!"
}

encoded_jwt = jwt.encode(payload, private_pem, algorithm="RS256")
print("JWT:", encoded_jwt)

# ========================================Parte 2========================================
# Verificar un JWT firmado
try:
    decoded_jwt = jwt.decode(encoded_jwt, public_pem, algorithms=["RS256"])
    print("Payload:", decoded_jwt)
except jwt.PyJWTError as e:
    print("Verification failed:", str(e))
