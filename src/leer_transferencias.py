from cryptography.fernet import Fernet

def load_key():
    with open("secret.key", "rb") as f:
        return f.read()

def leer_transferencias():
    key = load_key()
    cipher = Fernet(key)

    with open("transferencias.txt", "rb") as f:
        for linea in f:
            try:
                original = cipher.decrypt(linea.strip())
                print("Transferencia:", original.decode())
            except Exception as e:
                print("Error al descifrar una línea:", e)

if __name__ == "__main__":
    leer_transferencias()