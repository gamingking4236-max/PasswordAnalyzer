import hashlib
import requests


def check_password_breach(password):
    # Password ka SHA-1 hash locally generate hoga
    sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()

    # Hash ko 2 parts mein divide karna
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]

    # Have I Been Pwned API
    url = f"https://api.pwnedpasswords.com/range/{prefix}"

    try:
        response = requests.get(
            url,
            headers={"Add-Padding": "true"},
            timeout=5
        )

        response.raise_for_status()

        # API se aaye hashes ko check karna
        for line in response.text.splitlines():
            hash_suffix, count = line.split(":")

            if hash_suffix == suffix:
                return {
                    "breached": True,
                    "count": int(count)
                }

        return {
            "breached": False,
            "count": 0
        }

    except requests.RequestException:
        return {
            "breached": None,
            "count": 0
        }