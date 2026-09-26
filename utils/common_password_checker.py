import os


def is_common_password(password):
    file_path = os.path.join(
        os.path.dirname(os.path.dirname(__file__)),
        "data",
        "common_passwords.txt"
    )

    try:
        with open(file_path, "r", encoding="utf-8") as file:
            common_passwords = {
                line.strip().lower()
                for line in file
                if line.strip()
            }

        return password.lower() in common_passwords

    except FileNotFoundError:
        return False