import http.server
import ssl
import json
import urllib.parse
import html
import secrets
import bcrypt
from hash_conSalt import password, hashed
from sessions import( create_session, get_session, delete_session, regenerate_session, load_sessions,is_session_valid,validate_csrf)
from security import validate_csrf, sanitize_input
from urllib.parse import unquote_plus
from cryptography.fernet import Fernet

CSRF_TOKEN = secrets.token_hex(16)  # Token CSRF global para demostración (en producción debería ser por sesión)



# Reiniciar sessions.json al arrancar el servidor
with open("sessions.json", "w") as f:
    f.write("[]")
# Diccionario de usuarios válidos
USERS = {
    "admin": b'$2b$12$UfGe9ISL8AbTFXcXUB7kreyu4J5ry7W911vr4gSutfoGCy4Jod24e',  # Hash bcrypt de "admin123"
    "nicolas": "seguridad2026",
    "prueba": "abc123"
}
# Lista global para comentarios (vulnerable a Stored XSS)
COMMENTS=[]

# Función para validar credenciales
def check_login(username, password):
    if username in USERS and USERS[username] == password:
        return True
    return False

class CookieHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        cookies = self.headers.get("Cookie")
        session_id = None

        if cookies and "sessionId=" in cookies:
            session_id = cookies.split("sessionId=")[1].split(";")[0]

        # 🔒 Validación de timeout de sesión
        if session_id and not is_session_valid(session_id):
          self.send_response(401)
          self.send_header("Content-type", "text/html; charset=utf-8")
          self.end_headers()
          self.wfile.write("Sesión expirada. Por favor, inicie sesión nuevamente.".encode("utf-8"))
          return
          # --- NUEVO ENDPOINT: comentarios vulnerables ---
        if self.path == "/comment":
            self.send_response(200)
            self.send_header("Content-type", "text/html; charset=utf-8")
            self.end_headers()

            page = f"""
            <html>
              <body>
                <h1>Comentarios</h1>
                <form action="/comment" method="POST">
                  <input type ="hidden" name="csrf_token" value="{CSRF_TOKEN}">
                  <input type="text" name="msg">
                  <input type="submit" value="Enviar">
                </form>
                <h2>Mensajes guardados:</h2>
                <ul>
             """
            for c in COMMENTS:
                
               #page += f"<li>{c}</li>" #⚠️ Vulnerable: se muestra sin sanitizar

               page +=f"<li>{html.escape(c)}</li>" #✅ Seguro: se escapa antes de mostrar

            page += "</ul></body></html>"

            self.wfile.write(page.encode("utf-8"))
            return
        # --- FIN NUEVO ENDPOINT ---

         # Endpoint de logout
        if self.path == "/logout":
            if session_id:
                delete_session(session_id)
            self.send_response(200)
            self.send_header("Content-type", "text/html; charset=utf-8")
            self.send_header("Set-Cookie", "sessionId=deleted; Secure; HttpOnly; SameSite=Strict; Max-Age=0")
            self.end_headers()
            mensaje = "<html><body><h1>Sesión cerrada correctamente</h1></body></html>"
            self.wfile.write(mensaje.encode("utf-8"))
            return
        # Endpoint vulnerable a XSS
        if self.path.startswith("/search"):
            query = self.path.split("?q=")[-1]
            mensaje = f"<html><body><h1>Resultados para: {query}</h1></body></html>"
            self.send_response(200)
            self.send_header("Content-type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(mensaje.encode("utf-8"))
            return
        # Endpoint de prueba XSS
        if self.path == "/xss":
            self.send_response(200)
            self.send_header("Content-type", "text/html; charset=utf-8")
            self.end_headers()
            mensaje = """
            <html>
              <body>
                <h1>Prueba XSS</h1>
                <script>
                  alert("Intento de leer cookie: " + document.cookie);
                </script>
              </body>
            </html>
            """
            self.wfile.write(mensaje.encode("utf-8"))
            return

        # Endpoint de login (formulario)
        if self.path == "/login" and self.command == "GET":
          #Mostrar formulario de login
            self.send_response(200)
            self.send_header("Content-type", "text/html; charset=utf-8")
            self.end_headers()
            login_form = """
            <html>
              <body>
               <h1>Login</h1>
               <form action="/login" method="POST">
                Usuario: <input type="text" name="username"><br>
                Contraseña: <input type="password" name="password"><br>
                <input type="submit" value="Ingresar">
               </form>
             </body>
            </html>
            """
            self.wfile.write(login_form.encode("utf-8"))
            
      
          
        # Flujo normal de sesión
        if session_id and get_session(session_id):
            session = get_session(session_id)
            user_data = session["user"]
            csrf_token = session["csrf"]
            print("SESSION_ID:", session_id)
            print("SESSION:", get_session(session_id))
            mensaje = f"""
            <html>
              <body>
                <h1>Bienvenido de nuevo, {sanitize_input(user_data)}!</h1>
                <form action="/transfer" method="POST">
                  <input type="hidden" name="csrf_token" value="{csrf_token}">
                  <input type="submit" value="Simular transferencia segura">
                </form>
              </body>
            </html>
            """
            self.send_response(200)
            self.send_header("Content-type", "text/html; charset=utf-8")
            self.send_header("Set-Cookie",f"sessionId={session_id};Secure;HttpOnly;SameSite=Strict;Max-Age=30")
            self.end_headers()
        else:
            session_id, user_data, csrf_token = create_session()
            mensaje = f"""
            <html>
              <body>
                <h1>Nueva sesión creada: {sanitize_input(user_data)}</h1>
                <form action="/transfer" method="POST">
                  <input type="hidden" name="csrf_token" value="{csrf_token}">
                  <input type="submit" value="Simular transferencia segura">
                </form>
              </body>
            </html>
            """
            self.send_response(200)
            self.send_header("Content-type", "text/html; charset=utf-8")
            self.send_header("Set-Cookie", f"sessionId={session_id}; Secure; HttpOnly; SameSite=Strict; Max-Age=30")
            self.end_headers()

        self.wfile.write(mensaje.encode("utf-8"))

    def do_POST(self):
        cookies = self.headers.get("Cookie")
        session_id = None
        if cookies and "sessionId=" in cookies:
          session_id = cookies.split("sessionId=")[1].split(";")[0]
          
         # 🔒 Validación de timeout de sesión
        if session_id and not is_session_valid(session_id):
           self.send_response(401)
           self.send_header("Content-type", "text/html; charset=utf-8")
           self.end_headers()
           self.wfile.write("Sesión expirada. Por favor, inicie sesión nuevamente.".encode("utf-8"))
           return
         # --- NUEVO ENDPOINT: guardar comentario ---
        if self.path == "/comment":
            length = int(self.headers.get("Content-Length"))
            post_data = self.rfile.read(length).decode("utf-8")

         # Parser correcto
            import urllib.parse
            params = urllib.parse.parse_qs(post_data)

         # 1. Obtener token
            token = params.get("csrf_token", [""])[0]
            msg = params.get("msg", [""])[0]
            print("POST_DATA:", post_data)
            print("PARAMS:",params)
            print("TOKEN_RECIBIDO:", token)
            print("TOKEN_ESPERADO:", CSRF_TOKEN)
         # 2. Validar token
            if token != CSRF_TOKEN:
              self.send_response(403)
              self.end_headers()
              self.wfile.write(b"CSRF token invalido")
              return

         # 3. Procesar comentario
        
            decode_msg = unquote_plus(msg)
            COMMENTS.append(decode_msg)

         # 4. Redirigir
            self.send_response(303)
            self.send_header("Location", "/comment")
            self.end_headers()
            return
         # --- FIN NUEVO ENDPOINT ---



         # Endpoint de transferencia protegida con CSRF
        if self.path == "/transfer":
           cookies = self.headers.get("Cookie")
           session_id = None
           if cookies and "sessionId=" in cookies:
               session_id = cookies.split("sessionId=")[1].split(";")[0]

           length = int(self.headers.get("Content-Length"))
           post_data = self.rfile.read(length).decode("utf-8")

           import urllib.parse
           params = urllib.parse.parse_qs(post_data)

           csrf_token = params.get("csrf_token", [""])[0]

           if not csrf_token:
               self.send_response(400)  # Bad Request
               self.send_header("Content-type", "text/html; charset=utf-8")
               self.end_headers()
               mensaje = "<html><body><h1>Falta token CSRF ❌</h1></body></html>"
               self.wfile.write(mensaje.encode("utf-8"))
               return
           
           #Validación de sesión y token CSRF
           
           session = get_session(session_id)
           if not session:
              self.send_response(401)  # Unauthorized
              self.send_header("Content-type", "text/html; charset=utf-8")
              self.end_headers()
              mensaje = "<html><body><h1>Sesión no válida ❌</h1></body></html>"
              self.wfile.write(mensaje.encode("utf-8"))
              return
        
         #Cifrado AES/Fernet
           key= load_key() #funcion definida fuera de la clase
           cipher = Fernet(key) #import ya esta arriba del archivo
           
           monto= params.get("monto",[""])[0]
           cuenta= params.get("cuenta",[""])[0]
           datos = f"Transferencia de ${monto} a la cuenta {cuenta}"
           
           datos_cifrados = cipher.encrypt(datos.encode())
           with open("transferencias.txt","ab")as f:
              f.write(datos_cifrados + b"\n")
              
           #Respuesta al cliente
           self.send_response(200)
           self.send_header("Content-type", "text/html; charset=utf-8")
           self.end_headers()
           mensaje = "<html><body><h1>Transferencia simulada con éxito ✅ (datos cifrados)</h1></body></html>"   
           self.wfile.write(mensaje.encode("utf-8"))
           
        # Endpoint de login (validación de credenciales)
        if self.path == "/login":
            length = int(self.headers.get("Content-Length"))
            post_data = self.rfile.read(length).decode("utf-8")
            
            import urllib.parse
            params = urllib.parse.parse_qs(post_data)
            
            username=params.get("username",[""])[0]
            password=params.get("password",[""])[0]
            
            # Verificacion con bcrypt
            stored_hash= USERS.get(username)
            if stored_hash and bcrypt.checkpw(password.encode(),stored_hash):
              
              #1.Si habia una sesión previa, la eliminamos
              if session_id:
                    delete_session(session_id)
                    
              #2.Creamos una sesión nueva y segura
              new_session_id,user_data,csrf_token = create_session(username)
              
              #3.Enviamos cookie segura
              self.send_response(302)
              self.send_header("Location", "/transferencias.html")
              self.send_header("Set-Cookie", f"sessionId={new_session_id}; HttpOnly; Secure; SameSite=Strict")
              self.end_headers()                 
            else:
              self.send_response(403)
              self.send_header("Content-type", "text/html; charset=utf-8")
              self.end_headers()
              self.wfile.write("Credenciales inválidas ❌".encode("utf-8")) 
              
        elif self.path == "/transferencias.html":
            try:
                with open("transferencias.html","rb")as f:
                  contenido = f.read()
                self.send_response(200)
                self.send_header("Content-type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(contenido)
            except FileNotFoundError:
                self.send_response(404)
                self.send_header("Content-type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write("Archivo no encontrado ❌".encode("utf-8"))    

# Cargar clave para cifrado simétrico (Fernet)             
def load_key():
  with open("secret.key","rb")as f:
    return f.read()
key = load_key()
cipher = Fernet(key)


# Configuración del servidor HTTPS
server_address = ('localhost', 4443)
httpd = http.server.HTTPServer(server_address, CookieHandler)

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certfile="localhost+1.pem", keyfile="localhost+1-key.pem")

httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
# Cargar sesiones previas desde el archivo JSON
load_sessions()
print("Servidor HTTPS con login multiusuario y sesiones en https://localhost:4443")
httpd.serve_forever()
