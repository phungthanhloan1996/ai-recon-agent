import requests

class GroqClient:
    def __init__(self, api_key, model="llama-3.3-70b-versatile"):
        self.api_key = api_key
        self.model = model

    def generate(self, prompt: str) -> str:
        url = "https://api.groq.com/openai/v1/chat/completions"

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }

        data = {
            "model": self.model,
            "messages": [
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.3
        }

        res = requests.post(url, headers=headers, json=data, timeout=15)

        if res.status_code != 200:
            raise Exception(f"Groq error: {res.text}")

        return res.json()["choices"][0]["message"]["content"]
