from dotenv import load_dotenv
import os

load_dotenv()

api_key = os.getenv("GROQ_API_KEY")

if api_key:
    print("✅ API Key loaded:", api_key[:10] + "...")
else:
    print("❌ API Key NOT loaded.")