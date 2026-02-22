def validate_csrf(session, token_received):
    """Valida que el token CSRF recibido coincida con el de la sesión"""
    if not session:
        return False
    return session.get("csrf") == token_received

def sanitize_input(value):
    """Ejemplo de sanitización básica para evitar inyecciones"""
    return value.replace("<", "&lt;").replace(">", "&gt;")