import bcrypt

# Contraseña original
password = b"admin123"

# Generar hash con salt automático
hashed = bcrypt.hashpw(password, bcrypt.gensalt())

print("Hash bcrypt:", hashed)