import secrets
import string


def generate_password(length=16, use_uppercase=True, use_numbers=True, use_symbols=True):
    characters = string.ascii_lowercase

    if use_uppercase:
        characters += string.ascii_uppercase

    if use_numbers:
        characters += string.digits

    if use_symbols:
        characters += "!@#$%^&*()-_=+"

    password = "".join(
        secrets.choice(characters)
        for _ in range(length)
    )

    return password


def generate_passphrase(word_count=4):
    words = [
        "river", "mountain", "forest", "ocean",
        "tiger", "eagle", "dragon", "sun",
        "moon", "cloud", "star", "thunder",
        "apple", "coffee", "planet", "rocket",
        "castle", "garden", "winter", "summer"
    ]

    selected_words = [
        secrets.choice(words)
        for _ in range(word_count)
    ]

    number = secrets.randbelow(100)

    return "-".join(selected_words) + "-" + str(number)