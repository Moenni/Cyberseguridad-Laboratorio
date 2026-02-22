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
- Clonar el repositorio:
git clone https://github.com/Moenni/Cyberseguridad-Laboratorio
cd Cyberseguridad-Laboratorio
- Crear entorno virtual:
python3 -m venv venv
source venv/bin/activate   # Linux/Mac
venv\Scripts\activate      # Windows
- Instalar dependencias:
Este proyecto usa solo librerías estándar de Python, no requiere paquetes externos.
- Generar certificados HTTPS con mkcert:
mkcert localhost


- Esto generará localhost+1.pem y localhost+1-key.pem.
▶️ Uso- Iniciar el servidor:
python server_https.py


- El servidor quedará disponible en:
https://localhost:4443
- Endpoints disponibles:
- / → Crea o recupera sesión.
- /login → Formulario de login con credenciales (admin / 1234).
- /transfer → Simula acción protegida con token CSRF.
- /logout → Cierra sesión y elimina cookie.
- /xss → Simula ataque XSS (bloqueado por sanitización y HttpOnly).
- csrf_test.html → Página externa para simular ataque CSRF.

🧪 Pruebas de seguridad
- Login correcto: credenciales válidas → 200 OK.
- Login incorrecto: credenciales inválidas → 401 Unauthorized.
- Transferencia legítima: token CSRF válido → 200 OK.
- Transferencia externa (CSRF): token inválido → 403 Forbidden.
- Sesión inválida / logout: cookie expirada → 401 Unauthorized.
- XSS: en /xss, el alert no muestra la cookie gracias a HttpOnly.
👉 Capturas de pantalla en la pestaña Network del navegador muestran los códigos HTTP cambiando según el escenario.

📓 Diario de prácticas
Cada paso se documenta con:
- Acción realizada: ej. implementar login con credenciales.
- Resultado: ej. el servidor devuelve 200 OK en login correcto y 401 Unauthorized en login incorrecto.
- Reflexión: ej. aprendí que los códigos HTTP son tan importantes como los mensajes visibles para entender el estado de la sesión.

🔎 Diagrama del flujo de sesión y seguridad
(Ya lo tenés, lo mantenemos igual porque está muy claro).

🔮 Próximos pasos
- Consolidar documentación final en un portfolio técnico con capturas y reflexiones.
- Extender el login para múltiples usuarios.
- Explorar integración con base de datos para persistencia de sesiones.
