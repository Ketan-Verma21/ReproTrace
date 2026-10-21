"""Google Gemini provider, called over HTTPS with the standard library (no SDK dependency).

The key is read from GEMINI_API_KEY and sent only in the ``x-goog-api-key`` header, never in
the URL, so it cannot appear in error messages or logs. Tests pass a fake ``opener``; the
real API is never called from tests (Rules.md 7).
"""

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from typing import Any

from reprotrace.errors import EXIT_ENVIRONMENT_ERROR, AIError

API_URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
KEY_ENV = "GEMINI_API_KEY"
MODEL_ENV = "REPROTRACE_GEMINI_MODEL"
# An alias that follows Google's current Flash model, which the free tier covers.
DEFAULT_MODEL = "gemini-flash-latest"
TIMEOUT_S = 90.0

Opener = Callable[..., Any]

_HTTP_HINTS = {
    400: "Check the model name (--model or REPROTRACE_GEMINI_MODEL) and that the key is valid.",
    401: "The API key was rejected. Create a new one in Google AI Studio.",
    403: "The API key was rejected or lacks access to this model.",
    404: "The model was not found. Try --model gemini-flash-latest.",
    429: "Rate limit or free-tier quota reached. Wait a minute and try again.",
}


class GeminiProvider:
    """Sends one prompt and returns the model's text (a JSON document)."""

    name = "gemini"

    def __init__(
        self,
        api_key: str,
        model: str = DEFAULT_MODEL,
        timeout: float = TIMEOUT_S,
        opener: Opener = urllib.request.urlopen,
    ) -> None:
        self.model = model
        self._api_key = api_key
        self._timeout = timeout
        self._opener = opener

    @classmethod
    def from_env(cls, model: str | None = None) -> "GeminiProvider":
        """Provider configured from the environment; AIError (exit 2) if no key is set."""
        key = os.environ.get(KEY_ENV, "").strip()
        if not key:
            raise AIError(
                f"{KEY_ENV} is not set, so no AI explanation can be generated.",
                hint=(
                    "Create a key in Google AI Studio and run: export GEMINI_API_KEY=... "
                    "Everything else in ReproTrace works without it."
                ),
                exit_code=EXIT_ENVIRONMENT_ERROR,
            )
        return cls(key, model or os.environ.get(MODEL_ENV) or DEFAULT_MODEL)

    def request_body(self, system: str, prompt: str, schema: dict) -> dict:
        return {
            "systemInstruction": {"parts": [{"text": system}]},
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "generationConfig": {
                "temperature": 0.2,
                "responseMimeType": "application/json",
                "responseSchema": schema,
            },
        }

    def generate(self, system: str, prompt: str, schema: dict) -> str:
        """Call generateContent; return the text of the first candidate."""
        url = API_URL.format(model=urllib.parse.quote(self.model, safe=""))
        request = urllib.request.Request(
            url,
            data=json.dumps(self.request_body(system, prompt, schema)).encode(),
            headers={"Content-Type": "application/json", "x-goog-api-key": self._api_key},
            method="POST",
        )
        try:
            with self._opener(request, timeout=self._timeout) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as error:
            raise AIError(
                f"Gemini API returned HTTP {error.code}: {_api_message(error)}",
                hint=_HTTP_HINTS.get(error.code),
            ) from error
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            raise AIError(
                f"Could not reach the Gemini API: {error}",
                hint="Check the network connection and try again.",
            ) from error
        except json.JSONDecodeError as error:
            raise AIError("The Gemini API returned a response that is not JSON.") from error
        return _candidate_text(payload)


def _api_message(error: urllib.error.HTTPError) -> str:
    try:
        body = json.loads(error.read().decode("utf-8"))
        return str(body["error"]["message"])[:300]
    except (OSError, ValueError, KeyError, TypeError):
        return error.reason if isinstance(error.reason, str) else "no details"


def _candidate_text(payload: dict) -> str:
    candidates = payload.get("candidates") or []
    if not candidates:
        reason = (payload.get("promptFeedback") or {}).get("blockReason", "no candidates")
        raise AIError(f"Gemini returned no answer ({reason}).")
    candidate = candidates[0]
    parts = (candidate.get("content") or {}).get("parts") or []
    text = "".join(part.get("text", "") for part in parts if isinstance(part, dict))
    if not text.strip():
        raise AIError(f"Gemini returned an empty answer ({candidate.get('finishReason', '?')}).")
    if candidate.get("finishReason") not in (None, "STOP"):
        raise AIError(
            f"Gemini stopped early ({candidate['finishReason']}); the answer is incomplete."
        )
    return text
