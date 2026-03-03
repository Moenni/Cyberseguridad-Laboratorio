import secrets
import json 
import os
import time


SESSION_FILE = "sessions.json"
sessions = {}

# Cargar sesiones desde archivo al iniciar
def load_sessions():
    global sessions
    if os.path.exists(SESSION_FILE):
        with open(SESSION_FILE,"r")as f:
            try:
                data = json.load(f)
                if isinstance(data, dict):
                    sessions = data
                else:
                    sessions = {} # Si no es dict, lo reseteamos
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
    sessions[session_id] = {"user": user_data, "csrf": csrf_token,"last_activity":time.time()}
    save_sessions()
    return session_id, user_data, csrf_token
def is_session_valid(session_id, timeout=300):  # 300 segundos = 5 min
    import time
    session = get_session(session_id)
    if not session:
        return False
    if time.time() - session.get("last_activity", 0) > timeout:
        delete_session(session_id)
        return False
    # refrescar actividad
    session["last_activity"] = time.time()
    save_sessions()
    return True

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