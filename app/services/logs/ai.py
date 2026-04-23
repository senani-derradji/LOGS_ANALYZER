import os
import json
from pathlib import Path

from openai import OpenAI
from app.utils.logger import logger
from app.core.config import settings

HF_TOKEN = settings.HF_TOKEN

if not HF_TOKEN:
    logger.error("HF_TOKEN is not set in environment for ai_analyzer")

client = OpenAI(
    base_url="https://router.huggingface.co/v1",
    api_key=HF_TOKEN,
)


def _extract_json_from_text(text: str) -> dict | None:

    if not text:
        return None

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    stripped = text.strip()
    if (stripped.startswith('"') and stripped.endswith('"')) or \
       (stripped.startswith("'") and stripped.endswith("'")):
        try:
            unescaped = json.loads(stripped)
            return json.loads(unescaped)
        except json.JSONDecodeError:
            return None

    return None


def ai_analyzer(logs_dataset: str) -> dict | None:

    if not HF_TOKEN:
        logger.error("HF_TOKEN missing, aborting ai_analyzer")
        return None

    system_prompt = (
        "You are an advanced SOC (Security Operations Center) log analysis engine.\n"
        "\n"
        "STRICT RULES:\n"
        "- Return ONLY valid JSON\n"
        "- No markdown\n"
        "- No explanations outside JSON\n"
        "- No comments\n"
        "- No extra text\n"
        "- JSON must be valid and parsable\n"
        "\n"
        "TASK:\n"
        "Analyze logs and generate deep technical insights.\n"
        "\n"
        "FOR EACH IMPORTANT OR SUSPICIOUS LOG:\n"
        "- Explain clearly what happened\n"
        "- Identify if it is normal, error, or security issue\n"
        "- Detect possible attacks (brute-force, abuse, scanning)\n"
        "- Identify server-side vs client-side issues\n"
        "- Provide probable root cause\n"
        "- Suggest actionable fix or mitigation\n"
        "\n"
        "DETECTION RULES:\n"
        "- HTTP 5xx → server failure (critical)\n"
        "- HTTP 4xx → client error or possible malicious request\n"
        "- Repeated failures → possible brute-force attack\n"
        "- Authentication errors → security risk\n"
        "- Unknown patterns → anomaly\n"
        "\n"
        "LOG TYPES:\n"
        "- web (HTTP requests)\n"
        "- system (OS / services)\n"
        "- security (auth / ssh / firewall)\n"
        "- application (JSON logs)\n"
        "\n"
        "IMPORTANT:\n"
        "- Focus on abnormal or important logs\n"
        "- Ignore normal INFO logs unless useful\n"
        "\n"
        "OUTPUT:\n"
        "- Each 'note' must be a clear, detailed, professional explanation\n"
        "- Include cause + risk + recommendation in ONE sentence if possible\n"
        "\n"
        "STRICT JSON ONLY."
    )

    user_prompt = f"""Analyze this logs dataset:

{logs_dataset}

Return ONLY this format and nothing else:

{{
  "AI": [
    {{
      "index": 0,
      "note": "..."
    }}
  ]
}}"""

    try:
        completion = client.chat.completions.create(
            model="openai/gpt-oss-120b:groq",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0,
        )
    except Exception as e:
        logger.error(f"AI request to HF router failed: {e}")
        return None

    try:
        message = completion.choices[0].message
        content = message.content
    except (IndexError, AttributeError, KeyError) as e:
        logger.error(f"Unexpected AI response structure: {e} | completion={completion}")
        return None

    parsed = _extract_json_from_text(content)
    if parsed is None:
        logger.error(f"Could not parse AI JSON content: {content}")
        return None

    if not isinstance(parsed, dict) or "AI" not in parsed:
        logger.error(f"AI JSON missing 'AI' key: {parsed}")
        return None

    return parsed