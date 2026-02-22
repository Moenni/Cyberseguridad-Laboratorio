import http.server
import ssl
from sessions import create_session, get_session, delete_session,regenerate_session

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
        # Endpoint de login (regenerar sesión)
        if self.path == "/login":
          if session_id:
             new_session_id, user_data = regenerate_session(session_id)
             self.send_response(200)
             self.send_header("Content-type", "text/html; charset=utf-8")
             self.send_header("Set-Cookie", f"sessionId={new_session_id}; Secure; HttpOnly; SameSite=Strict; Max-Age=30")
             self.end_headers()
             mensaje = f"<html><body><h1>Sesión regenerada para {user_data}</h1></body></html>"
             self.wfile.write(mensaje.encode("utf-8"))
             return

        # Flujo normal de sesión
        if session_id and get_session(session_id):
            user_data = get_session(session_id)
            mensaje = f"<html><body><h1>Bienvenido de nuevo, {user_data}!</h1></body></html>"
            self.send_response(200)
            self.send_header("Content-type", "text/html; charset=utf-8")
            self.end_headers()
        else:
            session_id, user_data = create_session()
            mensaje = f"<html><body><h1>Nueva sesión creada: {user_data}</h1></body></html>"
            self.send_response(200)
            self.send_header("Content-type", "text/html; charset=utf-8")
            # Cookie expira en 30 segundos
            self.send_header("Set-Cookie", f"sessionId={session_id}; Secure; HttpOnly; SameSite=Strict; Max-Age=30")
            self.end_headers()

        self.wfile.write(mensaje.encode("utf-8"))

server_address = ('localhost', 4443)
httpd = http.server.HTTPServer(server_address, CookieHandler)

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certfile="localhost+1.pem", keyfile="localhost+1-key.pem")

httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

print("Servidor HTTPS con sesiones modularizadas en https://localhost:4443")
httpd.serve_forever()