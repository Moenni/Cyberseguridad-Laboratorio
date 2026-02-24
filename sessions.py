import secrets
import json 
import os

SESSION_FILE = "sessions.json"
sessions = {}

# Cargar sesiones desde archivo al iniciar
def load_sessions():
    global sessions
    if os.path.exists(SESSION_FILE):
        with open(SESSION_FILE,"r")as f:
            try:
                sessions = json.load(f)
            except json.JSONDecodeError:
                sessions = {}
    else:
        sessions = {}
# Guardar sesiones en archivo
def save_sessions():
    with open(SESSION_FILE,"w")as f:
        json.dump(sessions,f)
                
def create_session(user_data=None):
    session_id = secrets.token_hex(16)
    if not user_data:
        user_data = f"Usuario -{len(sessions)+1}"
    csrf_token = secrets.token_hex(16)
    sessions[session_id] = {"user": user_data, "csrf": csrf_token}
    save_sessions()
    return session_id, user_data, csrf_token

def get_session(session_id):
    return sessions.get(session_id)

def delete_session(session_id):
    if session_id in sessions:
        del sessions[session_id]
        save_sessions()

def regenerate_session(old_session_id):
    if old_session_id in sessions:
        user_data = sessions[old_session_id]["user"]
        del sessions[old_session_id]
        new_session_id = secrets.token_hex(16)
        csrf_token = secrets.token_hex(16)
        sessions[new_session_id] = {"user": user_data, "csrf": csrf_token}
        return new_session_id, user_data, csrf_token
    return create_session()