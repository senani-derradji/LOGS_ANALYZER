import os, sys, re, json, requests

from dotenv import load_dotenv
from pathlib import Path

env_path = Path(__file__).resolve().parent / ".env"
load_dotenv(dotenv_path=env_path)

BASE_URL = os.getenv("BASE_URL") ; API_KEY = os.getenv("API_KEY")


def extract_json(text: str):
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if match:
        return match.group(0)
    return None



def ai_analyzer(data):

    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json",
    }

    payload = {
        "model": "allenai/Olmo-3-7B-Instruct:publicai",
        "messages": [
            {
                "role": "system",
                "content": (
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
            },
            {
                "role": "user",
                "content": f"""
Analyze this logs dataset:

{data}

Return ONLY this format:

{{
  "AI": [
    {{
      "index": 0,
      "note": "..."
    }}
  ]
}}
"""
            }
        ],
        "temperature": 0
    }


    response = requests.post(BASE_URL, headers=headers, data=json.dumps(payload))
    result = response.json()
    print("RESULT_01 :: ", result)

    content = result["choices"][0]["message"]["content"]

    clean_json = extract_json(content)

    if not clean_json:
        print("No valid JSON found")
        print(content)
        return None

    try:
        parsed = json.loads(clean_json)
    except json.JSONDecodeError:
        print("JSON parsing failed")
        print(clean_json)
        return None


    messages = [
        {
            "role": "user",
            "content": f"Re-check this logs dataset:\n{data}"
        },
        {
            "role": "assistant",
            "content": json.dumps(parsed)
        },
        {
            "role": "user",
            "content": "Return ONLY corrected final JSON."
        }
    ]

    payload["messages"] = messages

    response2 = requests.post(BASE_URL, headers=headers, data=json.dumps(payload))
    result2 = response2.json()
    print("RESULT_02 :: ", result2)

    final_content = result2["choices"][0]["message"]["content"]

    clean_final = extract_json(final_content)

    if not clean_final:
        print("Final response invalid JSON")
        print(final_content)
        return parsed

    try:
        final_parsed = json.loads(clean_final)
        return final_parsed

    except json.JSONDecodeError:
        print("Final JSON parse error")
        return parsed