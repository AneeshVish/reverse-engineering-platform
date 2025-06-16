import openai
import logging

class AIAssistant:
    def __init__(self, api_key=None):
        self.logger = logging.getLogger(__name__)
        if api_key:
            openai.api_key = api_key

    def analyze_code(self, code, context="Reverse engineering analysis"):
        """
        Use AI to analyze decompiled code.
        Returns AI-generated insights.
        """
        prompt = f"Analyze this code for security issues and functionality:\n{code}\n{context}"
        response = openai.ChatCompletion.create(
            model="gpt-4",
            messages=[{"role": "user", "content": prompt}]
        )
        return response.choices[0].message.content
