Proyecto: Servidor HTTPS con Gestión Segura de Sesiones
📌 Descripción
Este proyecto implementa un servidor HTTPS en Python que gestiona sesiones de usuario mediante cookies seguras. El objetivo es aprender y demostrar buenas prácticas de seguridad web, incluyendo protección contra ataques comunes como XSS, CSRF y Session Fixation.
Es un laboratorio práctico orientado a construir un portfolio técnico en ciberseguridad.

🎯 Objetivos
- Configurar un servidor HTTPS con certificados válidos.
- Implementar cookies seguras (Secure, HttpOnly, SameSite).
- Gestionar múltiples sesiones de usuario en paralelo.
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
├── security.py         # Funciones auxiliares de seguridad (futuro)
├── localhost+1.pem     # Certificado HTTPS generado con mkcert
├── localhost+1-key.pem # Clave privada del certificado
└── csrf_test.html      # Página externa para simular ataque CSRF



🚀 Instalación
1. Clonar el repositorio
git clone https://github.com/usuario/proyecto-sesiones.git
cd proyecto-sesiones


2. Crear entorno virtual
python3 -m venv venv
source venv/bin/activate   # Linux/Mac
venv\Scripts\activate      # Windows


3. Instalar dependencias
Este proyecto usa solo librerías estándar de Python, no requiere paquetes externos.
4. Generar certificados HTTPS
Instalar mkcert (github.com in Bing) y ejecutar:
mkcert localhost


Esto generará localhost+1.pem y localhost+1-key.pem.

▶️ Uso
1. Iniciar el servidor
python server_https.py


El servidor quedará disponible en:
https://localhost:4443


2. Endpoints disponibles
- / → Crea o recupera sesión.
- /logout → Cierra sesión y elimina cookie.
- /xss → Simula ataque XSS (bloqueado por HttpOnly).
- /login → Regenera sessionId (defensa contra Session Fixation).
- /transfer → Simula acción protegida con token CSRF.
- csrf_test.html → Página externa para simular ataque CSRF.

🧪 Pruebas de seguridad
- XSS: https://localhost:4443/xss → el alert no muestra la cookie gracias a HttpOnly.
- CSRF: abrir csrf_test.html → el navegador no envía la cookie gracias a SameSite=Strict.
- Session Fixation: entrar en /login → el servidor regenera el sessionId.
- CSRF avanzado: formulario en /transfer → valida token CSRF único por sesión.

📓 Diario de prácticas
Cada paso se documenta con:
- Acción realizada (ej. implementar logout).
- Resultado (ej. cookie eliminada correctamente).
- Reflexión (ej. aprendí que HttpOnly protege contra XSS).
Este diario forma parte del portfolio final.

🔮 Próximos pasos
- Refactorizar en módulos (security.py).
- Implementar sanitización de inputs y validaciones adicionales.
- Simular un flujo de login real con usuario/contraseña.
- Consolidar documentación final en un portfolio técnico.
