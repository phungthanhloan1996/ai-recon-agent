import requests

class GroqClient:
    def __init__(self, api_key, model="llama-3.3-70b-versatile"):
        self.api_key = api_key
        self.model = model

    def generate(self, prompt: str, system: str = None, temperature: float = 0.3) -> str:
        """Generate response from Groq API with optional system prompt"""
        url = "https://api.groq.com/openai/v1/chat/completions"

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }

        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        
        messages.append({"role": "user", "content": prompt})

        data = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature
        }

        res = requests.post(url, headers=headers, json=data, timeout=15)

        if res.status_code != 200:
            raise Exception(f"Groq error: {res.text}")

        return res.json()["choices"][0]["message"]["content"]
