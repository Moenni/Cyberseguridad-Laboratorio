import http.server
import ssl
from sessions import create_session, get_session, delete_session, regenerate_session
from security import validate_csrf, sanitize_input

class CookieHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        cookies = self.headers.get("Cookie")
        session_id = None

        if cookies and "sessionId=" in cookies:
            session_id = cookies.split("sessionId=")[1].split(";")[0]

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
        if self.path == "/login":
            self.send_response(200)
            self.send_header("Content-type", "text/html; charset=utf-8")
            self.end_headers()
            mensaje = """
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
            self.wfile.write(mensaje.encode("utf-8"))
            return

        # Flujo normal de sesión
        if session_id and get_session(session_id):
            session = get_session(session_id)
            user_data = session["user"]
            csrf_token = session["csrf"]
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
        # Endpoint de transferencia protegida con CSRF
        if self.path == "/transfer":
            cookies = self.headers.get("Cookie")
            session_id = None
            if cookies and "sessionId=" in cookies:
                session_id = cookies.split("sessionId=")[1].split(";")[0]

            length = int(self.headers.get("Content-Length"))
            post_data = self.rfile.read(length).decode("utf-8")
            params = dict(x.split("=") for x in post_data.split("&"))
            csrf_token = params.get("csrf_token")
            # Validar que el token CSRF exista
            if not csrf_token:
               self.send_response(400)  # Bad Request
               self.send_header("Content-type", "text/html; charset=utf-8")
               self.end_headers()
               mensaje = "<html><body><h1>Falta token CSRF ❌</h1></body></html>"
               self.wfile.write(mensaje.encode("utf-8"))
               return
            # Validar sesión y token CSRF
            
            session = get_session(session_id)
            if not session:
                self.send_response(401)  # Unauthorized
                self.send_header("Content-type", "text/html; charset=utf-8")
                mensaje = "<html><body><h1>Sesión no válida ❌</h1></body></html>"
            elif validate_csrf(session, params.get("csrf_token")):
                self.send_response(200)  # OK
                self.send_header("Content-type", "text/html; charset=utf-8")
                mensaje = "<html><body><h1>Transferencia realizada con éxito ✅</h1></body></html>"
            else:
                self.send_response(403)  # Forbidden
                self.send_header("Content-type", "text/html; charset=utf-8")
                mensaje = "<html><body><h1>Token CSRF inválido ❌</h1></body></html>"

            self.send_response(200)
            self.send_header("Content-type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(mensaje.encode("utf-8"))
            return

        # Endpoint de login (validación de credenciales)
        if self.path == "/login":
            length = int(self.headers.get("Content-Length"))
            post_data = self.rfile.read(length).decode("utf-8")
            params = dict(x.split("=") for x in post_data.split("&"))

            username = params.get("username")
            password = params.get("password")

            if username == "admin" and password == "1234":
                session_id, user_data, csrf_token = create_session()
                self.send_response(200)    #OK
                self.send_header("Content-type", "text/html; charset=utf-8")
                self.send_header("Set-Cookie", f"sessionId={session_id}; Secure; HttpOnly; SameSite=Strict; Max-Age=30")
                self.end_headers()
                mensaje = f"""
                <html>
                  <body>
                    <h1>Bienvenido {sanitize_input(username)} ✅</h1>
                    <form action="/transfer" method="POST">
                      <input type="hidden" name="csrf_token" value="{csrf_token}">
                      <input type="submit" value="Simular transferencia segura">
                    </form>
                  </body>
                </html>
                """
            else:
                self.send_response(401) #Unauthorized
                self.send_header("Content-type", "text/html; charset=utf-8")
                self.end_headers()
                mensaje = "<html><body><h1>Credenciales inválidas ❌</h1></body></html>"

            self.wfile.write(mensaje.encode("utf-8"))
            return

# Configuración del servidor HTTPS
server_address = ('localhost', 4443)
httpd = http.server.HTTPServer(server_address, CookieHandler)

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certfile="localhost+1.pem", keyfile="localhost+1-key.pem")

httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

print("Servidor HTTPS con login y sesiones en https://localhost:4443")
httpd.serve_forever()
