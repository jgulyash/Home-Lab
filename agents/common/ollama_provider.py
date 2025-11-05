"""
Ollama LLM Provider

Local LLM support using Ollama for cost savings and privacy.
Optimized for Apple Silicon (M4 Max).
"""

import os
import json
import logging
from typing import List, Dict, Any, Optional
import requests
from openai import OpenAI

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class OllamaProvider:
    """
    Local LLM provider using Ollama

    Supports multiple models running locally on Apple Silicon:
    - llama3.1:8b - Fast, efficient, good for most tasks
    - llama3.1:70b - High accuracy, requires more resources
    - mistral:7b - Fast and efficient
    - codellama:13b - Code-focused tasks
    - phi3:mini - Very fast, lightweight
    """

    def __init__(self, base_url: str = "http://localhost:11434"):
        self.base_url = base_url
        self.available = self._check_availability()
        logger.info(f"Ollama provider initialized (available: {self.available})")

    def _check_availability(self) -> bool:
        """Check if Ollama is running"""
        try:
            response = requests.get(f"{self.base_url}/api/tags", timeout=2)
            return response.status_code == 200
        except:
            return False

    def list_models(self) -> List[str]:
        """List available models"""
        try:
            response = requests.get(f"{self.base_url}/api/tags")
            response.raise_for_status()
            models = response.json().get('models', [])
            return [m['name'] for m in models]
        except Exception as e:
            logger.error(f"Failed to list models: {e}")
            return []

    def generate(
        self,
        prompt: str,
        model: str = "llama3.1:8b",
        temperature: float = 0.3,
        max_tokens: int = 2000,
        system: Optional[str] = None
    ) -> str:
        """
        Generate completion using local LLM

        Args:
            prompt: User prompt
            model: Model name (default: llama3.1:8b)
            temperature: Sampling temperature
            max_tokens: Maximum tokens to generate
            system: System message

        Returns:
            Generated text
        """
        try:
            payload = {
                "model": model,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": temperature,
                    "num_predict": max_tokens
                }
            }

            if system:
                payload["system"] = system

            response = requests.post(
                f"{self.base_url}/api/generate",
                json=payload,
                timeout=300  # 5 minute timeout for large models
            )
            response.raise_for_status()

            result = response.json()
            return result.get('response', '')

        except Exception as e:
            logger.error(f"Generation failed: {e}")
            raise

    def chat(
        self,
        messages: List[Dict[str, str]],
        model: str = "llama3.1:8b",
        temperature: float = 0.3,
        response_format: Optional[str] = None
    ) -> str:
        """
        Chat completion using local LLM

        Args:
            messages: List of message dicts with 'role' and 'content'
            model: Model name
            temperature: Sampling temperature
            response_format: 'json' for JSON output

        Returns:
            Generated response
        """
        try:
            payload = {
                "model": model,
                "messages": messages,
                "stream": False,
                "options": {
                    "temperature": temperature
                }
            }

            if response_format == "json":
                payload["format"] = "json"

            response = requests.post(
                f"{self.base_url}/api/chat",
                json=payload,
                timeout=300
            )
            response.raise_for_status()

            result = response.json()
            return result.get('message', {}).get('content', '')

        except Exception as e:
            logger.error(f"Chat failed: {e}")
            raise

    def pull_model(self, model: str) -> bool:
        """
        Download a model if not already available

        Args:
            model: Model name (e.g., 'llama3.1:8b')

        Returns:
            True if successful
        """
        try:
            logger.info(f"Pulling model: {model}")
            response = requests.post(
                f"{self.base_url}/api/pull",
                json={"name": model},
                stream=True,
                timeout=3600  # 1 hour for large downloads
            )

            for line in response.iter_lines():
                if line:
                    data = json.loads(line)
                    status = data.get('status', '')
                    if 'downloading' in status.lower():
                        logger.info(f"Downloading: {status}")

            logger.info(f"Model {model} ready")
            return True

        except Exception as e:
            logger.error(f"Failed to pull model: {e}")
            return False


class HybridLLMProvider:
    """
    Hybrid LLM provider that falls back to OpenAI if local model fails

    Strategy:
    1. Try local Ollama first (fast, free, private)
    2. Fall back to OpenAI if needed (slow tasks, complex reasoning)
    """

    def __init__(self):
        self.ollama = OllamaProvider()
        self.openai_key = os.getenv('OPENAI_API_KEY')
        self.openai_client = OpenAI(api_key=self.openai_key) if self.openai_key else None

        # Configuration
        self.use_local_first = os.getenv('USE_LOCAL_LLM', 'true').lower() == 'true'
        self.local_model = os.getenv('OLLAMA_MODEL', 'llama3.1:8b')

        logger.info(f"Hybrid LLM initialized (local_first: {self.use_local_first})")

    def chat_completion(
        self,
        messages: List[Dict[str, str]],
        temperature: float = 0.3,
        response_format: Optional[str] = None,
        prefer_cloud: bool = False
    ) -> str:
        """
        Chat completion with hybrid strategy

        Args:
            messages: Chat messages
            temperature: Sampling temperature
            response_format: 'json' for JSON output
            prefer_cloud: Force use of cloud LLM

        Returns:
            Generated response
        """

        # Try local first unless cloud preferred
        if self.use_local_first and not prefer_cloud and self.ollama.available:
            try:
                logger.info(f"Using local LLM: {self.local_model}")
                response = self.ollama.chat(
                    messages=messages,
                    model=self.local_model,
                    temperature=temperature,
                    response_format=response_format
                )
                logger.info("Local LLM succeeded")
                return response
            except Exception as e:
                logger.warning(f"Local LLM failed, falling back to OpenAI: {e}")

        # Fall back to OpenAI
        if self.openai_client:
            try:
                logger.info("Using OpenAI")

                kwargs = {
                    "model": "gpt-4" if prefer_cloud else "gpt-3.5-turbo",
                    "messages": messages,
                    "temperature": temperature
                }

                if response_format == "json":
                    kwargs["response_format"] = {"type": "json_object"}

                response = self.openai_client.chat.completions.create(**kwargs)
                return response.choices[0].message.content

            except Exception as e:
                logger.error(f"OpenAI also failed: {e}")
                raise

        raise Exception("No LLM provider available")

    def estimate_cost_savings(self, num_requests: int, avg_tokens: int = 1000) -> Dict[str, Any]:
        """
        Calculate cost savings from using local LLM

        Args:
            num_requests: Number of requests per month
            avg_tokens: Average tokens per request

        Returns:
            Cost comparison
        """
        # OpenAI pricing (approximate)
        gpt4_cost_per_1k = 0.03  # input + output average
        gpt35_cost_per_1k = 0.002

        # Calculate costs
        openai_monthly_cost = (num_requests * avg_tokens / 1000) * gpt4_cost_per_1k
        local_monthly_cost = 0  # Electricity negligible on M4 Mac

        savings = openai_monthly_cost - local_monthly_cost

        return {
            'requests_per_month': num_requests,
            'openai_cost': f"${openai_monthly_cost:.2f}",
            'local_cost': f"${local_monthly_cost:.2f}",
            'monthly_savings': f"${savings:.2f}",
            'annual_savings': f"${savings * 12:.2f}"
        }


# Recommended models for different tasks
RECOMMENDED_MODELS = {
    'fast': 'llama3.1:8b',          # Fast, general purpose (4GB RAM)
    'accurate': 'llama3.1:70b',      # High accuracy (40GB RAM) - for M4 Max!
    'efficient': 'mistral:7b',       # Very efficient (4GB RAM)
    'code': 'codellama:13b',         # Code tasks (8GB RAM)
    'lightweight': 'phi3:mini',      # Ultra fast (2GB RAM)
}


def setup_ollama_models(models: List[str] = ['llama3.1:8b']) -> None:
    """
    Download recommended models for the lab

    For M4 Max with 36GB RAM, you can run:
    - llama3.1:8b (4GB) - Fast general purpose
    - llama3.1:70b (40GB) - High accuracy (fits in your RAM!)
    - mistral:7b (4GB) - Efficient
    """
    ollama = OllamaProvider()

    if not ollama.available:
        logger.error("Ollama is not running. Start it first: brew services start ollama")
        return

    logger.info(f"Setting up models: {models}")

    for model in models:
        if model not in ollama.list_models():
            logger.info(f"Downloading {model}...")
            ollama.pull_model(model)
        else:
            logger.info(f"Model {model} already available")

    logger.info("Ollama setup complete!")


if __name__ == "__main__":
    # Test the hybrid provider
    provider = HybridLLMProvider()

    # Example usage
    messages = [
        {"role": "system", "content": "You are a cybersecurity expert."},
        {"role": "user", "content": "What is a brute force attack?"}
    ]

    response = provider.chat_completion(messages)
    print("\nResponse:", response)

    # Calculate cost savings
    savings = provider.estimate_cost_savings(num_requests=1000, avg_tokens=1500)
    print("\nCost Savings Analysis:")
    print(json.dumps(savings, indent=2))
