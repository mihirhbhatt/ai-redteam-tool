import os
import time

from core.target import BaseTargetAdapter, TargetResponse

class OpenAIAdapter(BaseTargetAdapter):
    def __init__(self, config: dict):
        super().__init__(config)
        from openai import OpenAI
        api_key_env = config.get("api_key_env") or "OPENAI_API_KEY"
        api_key = os.getenv(api_key_env)
        if not api_key:
            raise ValueError(f"API key environment variable {api_key_env!r} is not set")
        base_url = config.get("base_url")
        self.client = OpenAI(api_key=api_key, base_url=base_url)
        self.model = config.get("model", "gpt-4o")
        self.temperature = config.get("temperature", 0.7)
        self.max_tokens = config.get("max_tokens", 2048)
        self.timeout = config.get("timeout", 60)
    
    def query(self, prompt: str, **kwargs) -> TargetResponse:
        return self.query_with_system("You are a helpful assistant.", prompt, **kwargs)
    
    def query_with_system(self, system_prompt: str, user_prompt: str, **kwargs) -> TargetResponse:
        start = time.time()
        response = self.client.chat.completions.create(
            model=kwargs.get("model", self.model),
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt[:10000]},
            ],
            temperature=kwargs.get("temperature", self.temperature),
            max_tokens=kwargs.get("max_tokens", self.max_tokens),
            timeout=self.timeout,
        )
        latency = time.time() - start
        self.request_count += 1
        
        return TargetResponse(
            prompt=user_prompt,
            response=response.choices[0].message.content or "",
            model=kwargs.get("model", self.model),
            latency=latency,
            metadata={
                "finish_reason": response.choices[0].finish_reason,
                "usage": response.usage.model_dump() if response.usage else {},
            }
        )


class AnthropicAdapter(BaseTargetAdapter):
    def __init__(self, config: dict):
        super().__init__(config)
        import importlib
        anthropic = importlib.import_module("anthropic")
        api_key_env = config.get("api_key_env") or "ANTHROPIC_API_KEY"
        api_key = os.getenv(api_key_env)
        if not api_key:
            raise ValueError(f"API key environment variable {api_key_env!r} is not set")
        self.timeout = config.get("timeout", 60)
        self.client = anthropic.Anthropic(api_key=api_key, timeout=self.timeout)
        self.model = config.get("model", "claude-3-sonnet-20240229")
        self.max_tokens = config.get("max_tokens", 2048)
        self.temperature = config.get("temperature", 0.7)
    
    def query(self, prompt: str, **kwargs) -> TargetResponse:
        return self.query_with_system("You are a helpful assistant.", prompt, **kwargs)
    
    def query_with_system(self, system_prompt: str, user_prompt: str, **kwargs) -> TargetResponse:
        start = time.time()
        response = self.client.messages.create(
            model=kwargs.get("model", self.model),
            max_tokens=kwargs.get("max_tokens", self.max_tokens),
            temperature=kwargs.get("temperature", self.temperature),
            system=system_prompt,
            messages=[{"role": "user", "content": user_prompt[:10000]}],
        )
        latency = time.time() - start
        self.request_count += 1
        
        return TargetResponse(
            prompt=user_prompt,
            response="".join(
                block.text for block in response.content
                if getattr(block, "type", None) == "text"
            ),
            model=kwargs.get("model", self.model),
            latency=latency,
        )


class OllamaAdapter(BaseTargetAdapter):
    """Adapter for local models via Ollama."""
    def __init__(self, config: dict):
        super().__init__(config)
        self.base_url = (config.get("base_url") or "http://localhost:11434").rstrip("/")
        self.model = config.get("model", "llama3")
        self.timeout = config.get("timeout", 60)
    
    def query(self, prompt: str, **kwargs) -> TargetResponse:
        return self.query_with_system("You are a helpful assistant.", prompt, **kwargs)
    
    def query_with_system(self, system_prompt: str, user_prompt: str, **kwargs) -> TargetResponse:
        import requests
        start = time.time()
        
        resp = requests.post(
            f"{self.base_url}/api/chat",
            json={
                "model": kwargs.get("model", self.model),
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                "stream": False,
                "options": {
                    "temperature": kwargs.get("temperature", self.config.get("temperature", 0.7)),
                    "num_predict": kwargs.get("max_tokens", self.config.get("max_tokens", 2048)),
                },
            },
            timeout=self.timeout,
        )
        resp.raise_for_status()
        data = resp.json()
        latency = time.time() - start
        self.request_count += 1
        
        return TargetResponse(
            prompt=user_prompt,
            response=data.get("message", {}).get("content", ""),
            model=kwargs.get("model", self.model),
            latency=latency,
        )
