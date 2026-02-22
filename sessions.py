import secrets

sessions = {}

def create_session():
    session_id = secrets.token_hex(16)
    user_data = f"Usuario-{len(sessions)+1}"
    csrf_token = secrets.token_hex(16)
    sessions[session_id] = {"user": user_data, "csrf": csrf_token}
    return session_id, user_data, csrf_token

def get_session(session_id):
    return sessions.get(session_id)

def delete_session(session_id):
    if session_id in sessions:
        del sessions[session_id]

def regenerate_session(old_session_id):
    if old_session_id in sessions:
        user_data = sessions[old_session_id]["user"]
        del sessions[old_session_id]
        new_session_id = secrets.token_hex(16)
        csrf_token = secrets.token_hex(16)
        sessions[new_session_id] = {"user": user_data, "csrf": csrf_token}
        return new_session_id, user_data, csrf_token
    return create_session()