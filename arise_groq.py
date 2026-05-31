import requests
import os
from dotenv import load_dotenv

# Load API key from .env file
load_dotenv()
api_key = os.getenv("GROQ_API_KEY")

# Set headers
headers = {
    "Authorization": f"Bearer {api_key}",
    "Content-Type": "application/json"
}

# Conversation loop
print("ARISE is ready. Type 'exit' to quit.")
while True:
    user_input = input("You: ")
    
    if user_input.lower() in ["exit", "quit"]:
        print("ARISE: Goodbye 👋")
        break

    # Prepare data
    data = {
        "model": "llama-3.3-70b-versatile",
        "messages": [
            {"role": "user", "content": user_input}
        ]
    }

    # Send request to Groq API
    response = requests.post(
        "https://api.groq.com/openai/v1/chat/completions",
        headers=headers,
        json=data
    )

    # Display result
    if response.status_code == 200:
        reply = response.json()["choices"][0]["message"]["content"]
        print("ARISE:", reply.strip())
    else:
        print("ARISE Error:", response.status_code)
        print(response.text)