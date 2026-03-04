📌 README Técnico
Proyecto: Servidor HTTPS con Gestión Segura de Sesiones
Este proyecto implementa un servidor HTTPS en Python que gestiona sesiones de usuario mediante cookies seguras. El objetivo es aprender y demostrar buenas prácticas de seguridad web, incluyendo protección contra ataques comunes como XSS, CSRF y Session Fixation.
Es un laboratorio práctico orientado a construir un portfolio técnico en ciberseguridad.

🎯 Objetivos
- Configurar un servidor HTTPS con certificados válidos.
- Implementar cookies seguras (Secure, HttpOnly, SameSite).
- Gestionar múltiples sesiones de usuario en paralelo.
- Implementar login real con credenciales de usuario.
- Implementar logout manual y expiración automática de sesiones.
- Simular ataques comunes (XSS, CSRF, Session Fixation) y comprobar defensas.
- Documentar cada paso en un diario de prácticas.
- Refactorizar el código en módulos (server_https.py, sessions.py, security.py).
- Construir un portfolio técnico que muestre habilidades en seguridad web.
- Integrar teoría avanzada de hashing, cifrado y autenticación con práctica real.
- Consolidar documentación final en un portfolio para certificación.

🛠️ Estructura del proyecto
/proyecto-sesiones
│
├── server_https.py     # Lógica del servidor y endpoints
├── sessions.py         # Gestión de sesiones y tokens CSRF
├── security.py         # Funciones auxiliares de seguridad (sanitize_input, validate_csrf)
├── localhost+1.pem     # Certificado HTTPS generado con mkcert
├── localhost+1-key.pem # Clave privada del certificado
└── csrf_test.html      # Página externa para simular ataque CSRF



🚀 Instalación
git clone https://github.com/Moenni/Cyberseguridad-Laboratorio
cd Cyberseguridad-Laboratorio
python3 -m venv venv
source venv/bin/activate   # Linux/Mac
venv\Scripts\activate      # Windows


- Dependencias: solo librerías estándar de Python.
- Generar certificados HTTPS con mkcert:
mkcert localhost



▶️ Uso
- Iniciar el servidor:
python server_https.py


- Disponible en: https://localhost:4443
- Endpoints:
- / → Crea o recupera sesión.
- /login → Formulario de login (admin / 1234).
- /transfer → Acción protegida con token CSRF.
- /logout → Cierra sesión y elimina cookie.
- /xss → Simula ataque XSS (bloqueado por sanitización y HttpOnly).
- csrf_test.html → Página externa para simular ataque CSRF.

🧪 Pruebas de seguridad
- Login correcto: credenciales válidas → 200 OK.
- Login incorrecto: credenciales inválidas → 401 Unauthorized.
- Transferencia legítima: token CSRF válido → 200 OK.
- Transferencia externa (CSRF): token inválido → 403 Forbidden.
- Sesión inválida / logout: cookie expirada → 401 Unauthorized.
- XSS: payload escapado → se muestra como texto plano, no ejecuta.
- ZAP: hallazgos de cabeceras faltantes (CSP, HSTS, X-Frame-Options, etc.).
- Nmap: puerto 4443 abierto, servicio Python BaseHTTPServer, certificado válido.
- Wireshark: handshake TCP/TLS correcto, tráfico cifrado con TLS 1.3.

📓 Diario de prácticas
Cada fase documentada con:
- Acción realizada (ej. implementar login, lanzar escaneo ZAP).
- Resultado (ej. payload escapado, alerta ZAP de cabecera faltante).
- Reflexión (ej. importancia de sanitización y cabeceras de seguridad).

🔎 Diagrama del flujo de sesión y seguridad
(Se mantiene igual, mostrando login, token CSRF, cookies seguras, logout, etc.)

📍 Checkpoints de la Ruta de Formación
Fase 1 — Fundamentos técnicos
- Linux, permisos, usuarios, firewall, procesos.
- Configuración de entornos (VirtualBox, Kali, Python).
Fase 2 — Seguridad web práctica
- Login multiusuario, sesiones persistentes.
- Pruebas manuales de XSS, CSRF, Session Fixation.
- Defensas iniciales implementadas.
Fase 3 — Pentesting y herramientas
- Burp Suite: pruebas manuales.
- OWASP ZAP: escaneo automático.
- Nmap: puertos y servicios.
- Wireshark: tráfico cifrado.
Fase 4 — Teoría avanzada + práctica
- Hashing: MD5, SHA-256, bcrypt.
- Cifrado: AES, RSA.
- Autenticación: contraseñas, tokens, certificados.
- Mapas conceptuales y tablas comparativas.
Fase 5 — Portfolio y certificación
- Consolidación de documentación.
- Mini-mapas y guías reutilizables.
- Preparación para CompTIA Security+.
- Simulaciones de examen y portfolio profesional.

🔮 Próximos pasos
- Completar tablas comparativas de hashing y cifrado.
- Implementar cabeceras de seguridad faltantes (CSP, HSTS, etc.).
- Extender login a múltiples usuarios con persistencia en base de datos.
- Consolidar todo en portfolio técnico con capturas, reflexiones y checklist
