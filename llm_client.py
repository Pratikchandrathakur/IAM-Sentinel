import time
import logging
import requests
from openai import OpenAI
import config

log = logging.getLogger("cyberengine.llm")


class LLMUnavailable(RuntimeError):
    """Raised when the LLM backend cannot be reached after retries.

    Callers must treat this as a best-effort narrative failure — deterministic findings
    are always authoritative and returned regardless of LLM availability.
    """


class LLMClient:
    """Unified client for Ollama and OpenAI-compatible vLLM endpoints.

    Reliability: bounded timeout, capped retries with backoff, and a typed
    LLMUnavailable on hard failure so a model outage degrades gracefully instead of
    corrupting a security report with an error string.
    """

    def __init__(self, backend="ollama"):
        self.backend = backend.lower()
        self.vllm_client = None
        if self.backend == "vllm":
            self.vllm_client = OpenAI(base_url=config.VLLM_API_URL, api_key="not-needed")

    def query(self, prompt: str, system_prompt: str = None, model: str = None,
              stream: bool = False, temperature: float = 0.1) -> str:
        if self.backend == "vllm":
            return self._query_vllm(prompt, system_prompt, model, stream, temperature)
        return self._query_ollama(prompt, system_prompt, model, temperature)

    def _with_retries(self, fn, what: str):
        last_err = None
        for attempt in range(1, config.LLM_MAX_RETRIES + 2):  # initial try + retries
            try:
                return fn()
            except Exception as e:  # noqa: BLE001 - normalize to LLMUnavailable below
                last_err = e
                log.warning("LLM %s attempt %d failed: %s", what, attempt, e)
                if attempt <= config.LLM_MAX_RETRIES:
                    time.sleep(config.LLM_RETRY_BACKOFF_SECONDS * attempt)
        raise LLMUnavailable(f"{what} failed after {config.LLM_MAX_RETRIES + 1} attempts: {last_err}")

    def _query_ollama(self, prompt, system_prompt=None, model=None, temperature=0.1) -> str:
        target_model = model or config.DEFAULT_OLLAMA_MODEL
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": target_model,
            "messages": messages,
            "stream": False,
            "options": {"temperature": temperature},
        }

        def _call():
            resp = requests.post(config.OLLAMA_CHAT_URL, json=payload, timeout=config.LLM_TIMEOUT_SECONDS)
            if resp.status_code == 200:
                return resp.json().get("message", {}).get("content", "")
            # Fall back to the /generate endpoint for older Ollama builds.
            gen_payload = {
                "model": target_model,
                "prompt": f"{system_prompt}\n\n{prompt}" if system_prompt else prompt,
                "stream": False,
                "options": {"temperature": temperature},
            }
            res_gen = requests.post(config.OLLAMA_API_URL, json=gen_payload, timeout=config.LLM_TIMEOUT_SECONDS)
            res_gen.raise_for_status()
            return res_gen.json().get("response", "")

        return self._with_retries(_call, f"ollama[{target_model}]")

    def _query_vllm(self, prompt, system_prompt=None, model=None, stream=False, temperature=0.1):
        target_model = model or config.DEFAULT_VLLM_MODEL
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        def _call():
            response = self.vllm_client.chat.completions.create(
                model=target_model,
                messages=messages,
                stream=stream,
                temperature=temperature,
                max_tokens=2048,
                timeout=config.LLM_TIMEOUT_SECONDS,
            )
            if stream:
                return response
            return response.choices[0].message.content

        return self._with_retries(_call, f"vllm[{target_model}]")
