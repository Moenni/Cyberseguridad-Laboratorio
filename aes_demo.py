from cryptography.fernet import Fernet

#Generar una clave simétrica 

key = Fernet.generate_key()
cipher_suite = Fernet(key)

#Cifrar un mensaje

mensaje = b"Transferencia de $1000 a la cuenta 1234"
token = cipher_suite.encrypt(mensaje)
print("Mensaje cifrado:", token)

#Descifrar el mensaje

mensaje_descifrado = cipher_suite.decrypt(token)
print("Mensaje descifrado:", mensaje_descifrado.decode())
