import os
import requests
from dotenv import load_dotenv
import json
import base64
from PIL import Image
from io import BytesIO
import io
from urllib.parse import urlparse

load_dotenv(override=True)

BLOCKED_DOMAINS = [
    "maliciousbook.com",
    "evilvideos.com",
    "darkwebforum.com",
    "shadytok.com",
    "suspiciouspins.com",
    "ilanbigio.com",
]


def pp(obj):
    print(json.dumps(obj, indent=4))


def show_image(base_64_image):
    image_data = base64.b64decode(base_64_image)
    image = Image.open(BytesIO(image_data))
    image.show()


def calculate_image_dimensions(base_64_image):
    image_data = base64.b64decode(base_64_image)
    image = Image.open(io.BytesIO(image_data))
    return image.size


def sanitize_message(msg: dict) -> dict:
    """Return a copy of the message with image_url omitted for computer_call_output messages."""
    if msg.get("type") == "computer_call_output":
        output = msg.get("output", {})
        if isinstance(output, dict):
            sanitized = msg.copy()
            sanitized["output"] = {**output, "image_url": "[omitted]"}
            return sanitized
    return msg


def create_response_openai(**kwargs):
    url = "https://api.openai.com/v1/responses"
    headers = {
        "Authorization": f"Bearer {os.getenv('OPENAI_API_KEY')}",
        "Content-Type": "application/json",
    }

    openai_org = os.getenv("OPENAI_ORG")
    if openai_org:
        headers["Openai-Organization"] = openai_org

    response = requests.post(url, headers=headers, json=kwargs)

    if response.status_code != 200:
        print(f"Error: {response.status_code} {response.text}")

    return response.json()


def convert_azure_to_openai_format(azure_response):
    """
    Convert Azure OpenAI API response format to the standard OpenAI format
    to maintain compatibility with the rest of the application code.

    This function takes a response from Azure OpenAI and restructures it
    to match what the standard OpenAI API would return.
    """
    # Check if there's an error in the Azure response
    if "error" in azure_response and azure_response["error"] is not None:
        return {
            "error": {
                "message": str(azure_response["error"]),
                "type": "azure_api_error",
            }
        }

    # For successful responses, maintain the format that the agent expects
    # The main part the agent uses is the 'output' array
    return {
        "id": azure_response.get("id", ""),
        "object": azure_response.get("object", "response"),
        "created": azure_response.get("created_at", 0),
        "model": azure_response.get("model", ""),
        "output": azure_response.get("output", []),
        "usage": azure_response.get("usage", {}),
    }


def create_response_azure(**kwargs):
    """
    Alternative version of create_response that uses Azure OpenAI API.

    This function communicates with the Azure OpenAI endpoint instead of the standard OpenAI API.
    Requires AZURE_OPENAI_API_KEY and AZURE_OPENAI_ENDPOINT environment variables to be set.

    Parameters are the same as create_response:
    - model: The model ID to use
    - input: The conversation or text input
    - tools: List of tool definitions
    - temperature: Optional temperature parameter
    - truncation: How to handle truncation ("auto" by default)
    """
    # Get Azure-specific environment variables
    azure_api_key = os.getenv("AZURE_OPENAI_API_KEY")
    azure_endpoint = os.getenv("AZURE_OPENAI_ENDPOINT")
    api_version = os.getenv("AZURE_OPENAI_API_VERSION", "2025-03-01-preview")

    if not azure_api_key:
        raise ValueError("AZURE_OPENAI_API_KEY environment variable is required")

    # Construct the Azure OpenAI API URL
    url = f"{azure_endpoint}/openai/responses?api-version={api_version}"

    # Azure uses api-key header instead of Bearer token
    headers = {"api-key": azure_api_key, "Content-Type": "application/json"}

    # Send the request
    response = requests.post(url, headers=headers, json=kwargs)

    if response.status_code != 200:
        print(f"Error: {response.status_code} {response.text}")
        return {"error": response.text}

    # Convert the Azure response to OpenAI format
    azure_response = response.json()
    return convert_azure_to_openai_format(azure_response)


def create_response(**kwargs):
    return create_response_azure(**kwargs)


def check_blocklisted_url(url: str) -> None:
    """Raise ValueError if the given URL (including subdomains) is in the blocklist."""
    hostname = urlparse(url).hostname or ""
    if any(
        hostname == blocked or hostname.endswith(f".{blocked}")
        for blocked in BLOCKED_DOMAINS
    ):
        raise ValueError(f"Blocked URL: {url}")
