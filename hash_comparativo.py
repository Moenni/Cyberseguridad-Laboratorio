import hashlib
import bcrypt
from argon2 import PasswordHasher

# Texto de ejemplo
texto = "MiPasswordSeguro123"

print("=== Hashing comparativo ===\n")

# MD5
md5_hash = hashlib.md5(texto.encode()).hexdigest()
print("MD5:", md5_hash)

# SHA-1
sha1_hash = hashlib.sha1(texto.encode()).hexdigest()
print("SHA-1:", sha1_hash)

# SHA-256
sha256_hash = hashlib.sha256(texto.encode()).hexdigest()
print("SHA-256:", sha256_hash)

# bcrypt
bcrypt_hash = bcrypt.hashpw(texto.encode(), bcrypt.gensalt())
print("bcrypt:", bcrypt_hash.decode())

# Argon2
ph = PasswordHasher()
argon2_hash = ph.hash(texto)
print("Argon2:", argon2_hash)