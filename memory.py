import firebase_admin
from firebase_admin import credentials, db
import os
from dotenv import load_dotenv

load_dotenv()

# Initialize Firebase once
if not firebase_admin._apps:
    cred = credentials.Certificate("firebase_credentials.json")
    firebase_admin.initialize_app(cred, {
        'databaseURL': os.getenv("FIREBASE_URL")
    })

# Path in the database where memory is stored
MEMORY_PATH = "arise/memory"

# ----------------------------
# 🔵 Save Memory Function
# ----------------------------
def save_memory(key, value):
    try:
        ref = db.reference(f"{MEMORY_PATH}/{key}")
        ref.set(value)
        print(f"✅ Memory saved: {key} = {value}")
    except Exception as e:
        print(f"❌ Error saving memory: {e}")

# ----------------------------
# 🟢 Load Memory Function
# ----------------------------
def load_memory(key):
    try:
        ref = db.reference(f"{MEMORY_PATH}/{key}")
        value = ref.get()
        print(f"📥 Memory loaded: {key} = {value}")
        return value
    except Exception as e:
        print(f"❌ Error loading memory: {e}")
        return None

# ----------------------------
# 🔴 Delete Memory Function
# ----------------------------
def delete_memory(key):
    try:
        ref = db.reference(f"{MEMORY_PATH}/{key}")
        ref.delete()
        print(f"🗑 Memory deleted: {key}")
    except Exception as e:
        print(f"❌ Error deleting memory: {e}")