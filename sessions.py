import secrets

sessions = {}

def create_session():
    session_id = secrets.token_hex(16)
    sessions[session_id] = f"Usuario-{len(sessions)+1}"
    return session_id, sessions[session_id]

def get_session(session_id):
    return sessions.get(session_id)

def delete_session(session_id):
    if session_id in sessions:
        del sessions[session_id]

def regenerate_session(old_session_id):
    """Crea un nuevo sessionId y elimina el anterior"""
    if old_session_id in sessions:
        user_data = sessions[old_session_id]
        del sessions[old_session_id]
        new_session_id = secrets.token_hex(16)
        sessions[new_session_id] = user_data
        return new_session_id, user_data
    return create_session()