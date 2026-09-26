from flask import Flask, render_template, request

from zxcvbn import zxcvbn

from utils.breach_checker import check_password_breach
from utils.common_password_checker import is_common_password
from utils.password_generator import generate_password, generate_passphrase

from database.database import (
    create_table,
    save_password,
    get_password_history,
    is_password_reused,
    is_password_expired,
    get_password_expiry
)


app = Flask(__name__)


# =========================
# CREATE DATABASE TABLE
# =========================

create_table()


# =========================
# HOME PAGE
# =========================

@app.route("/")
def home():

    return render_template(
        "index.html"
    )


# =========================
# PASSWORD GENERATOR PAGE
# =========================

@app.route("/generator")
def generator():

    return render_template(
        "generator.html"
    )


# =========================
# PASSWORD HISTORY PAGE
# =========================

@app.route("/history")
def history():

    password_history = get_password_history()

    return render_template(
        "history.html",
        history=password_history
    )


# =========================
# GENERATE PASSWORD
# =========================

@app.route(
    "/generate-password",
    methods=["POST"]
)
def generate_password_route():

    length = int(
        request.form.get(
            "length",
            16
        )
    )

    use_uppercase = (
        request.form.get("uppercase") == "on"
    )

    use_numbers = (
        request.form.get("numbers") == "on"
    )

    use_symbols = (
        request.form.get("symbols") == "on"
    )

    generated_password = generate_password(
        length=length,
        use_uppercase=use_uppercase,
        use_numbers=use_numbers,
        use_symbols=use_symbols
    )

    save_password(
        generated_password,
        "generated"
    )

    expiry_date = get_password_expiry(
        generated_password
    )

    return render_template(
        "generator.html",
        generated_password=generated_password,
        expiry_date=expiry_date
    )


# =========================
# GENERATE PASSPHRASE
# =========================

@app.route(
    "/generate-passphrase",
    methods=["POST"]
)
def generate_passphrase_route():

    word_count = int(
        request.form.get(
            "word_count",
            4
        )
    )

    generated_passphrase = generate_passphrase(
        word_count
    )

    save_password(
        generated_passphrase,
        "passphrase"
    )

    expiry_date = get_password_expiry(
        generated_passphrase
    )

    return render_template(
        "generator.html",
        generated_password=generated_passphrase,
        expiry_date=expiry_date
    )


# =========================
# PASSWORD ANALYZER
# =========================

@app.route(
    "/analyze",
    methods=["POST"]
)
def analyze():

    password = request.form.get(
        "password",
        ""
    )


    # =========================
    # PASSWORD LENGTH
    # =========================

    length = len(password)


    # =========================
    # BASIC SECURITY SCORE
    # =========================

    score = 0


    if length >= 8:
        score += 1

    if length >= 12:
        score += 1

    if any(
        c.isupper()
        for c in password
    ):
        score += 1

    if any(
        c.islower()
        for c in password
    ):
        score += 1

    if any(
        c.isdigit()
        for c in password
    ):
        score += 1

    if any(
        not c.isalnum()
        for c in password
    ):
        score += 1


    # =========================
    # BASIC PASSWORD STRENGTH
    # =========================

    if score <= 2:

        strength = "Weak"

    elif score <= 4:

        strength = "Medium"

    elif score == 5:

        strength = "Strong"

    else:

        strength = "Very Strong"


    # =========================
    # ZXCVBN SMART ANALYSIS
    # =========================

    zxcvbn_result = zxcvbn(password)

    zxcvbn_score = zxcvbn_result["score"]

    zxcvbn_guesses = zxcvbn_result["guesses"]

    zxcvbn_crack_time = (
        zxcvbn_result["crack_times_display"]
        ["offline_slow_hashing_1e4_per_second"]
    )


    # =========================
    # SMART SUGGESTIONS
    # =========================

    suggestions = []


    if length < 8:

        suggestions.append(
            "Use at least 8 characters."
        )


    if length < 12:

        suggestions.append(
            "For better security, use 12 or more characters."
        )


    if not any(
        c.isupper()
        for c in password
    ):

        suggestions.append(
            "Add at least one uppercase letter (A-Z)."
        )


    if not any(
        c.islower()
        for c in password
    ):

        suggestions.append(
            "Add at least one lowercase letter (a-z)."
        )


    if not any(
        c.isdigit()
        for c in password
    ):

        suggestions.append(
            "Add at least one number (0-9)."
        )


    if not any(
        not c.isalnum()
        for c in password
    ):

        suggestions.append(
            "Add at least one special character (!, @, #, $, etc.)."
        )


    # Add zxcvbn feedback
    zxcvbn_feedback = zxcvbn_result.get(
        "feedback",
        {}
    )

    warning = zxcvbn_feedback.get(
        "warning",
        ""
    )

    feedback_suggestions = zxcvbn_feedback.get(
        "suggestions",
        []
    )


    if warning:

        suggestions.append(
            warning
        )


    for suggestion in feedback_suggestions:

        if suggestion not in suggestions:

            suggestions.append(
                suggestion
            )


    if not suggestions:

        suggestions.append(
            "Great! Your password meets the basic security requirements."
        )


    # =========================
    # DATA BREACH CHECK
    # =========================

    breach_result = check_password_breach(
        password
    )


    # =========================
    # COMMON PASSWORD CHECK
    # =========================

    common_password = is_common_password(
        password
    )


    # =========================
    # PASSWORD REUSE CHECK
    # =========================

    password_reused = is_password_reused(
        password
    )


    # =========================
    # PASSWORD EXPIRY CHECK
    # =========================

    password_expired = is_password_expired(
        password
    )

    expiry_date = get_password_expiry(
        password
    )


    # =========================
    # SAVE ANALYZED PASSWORD
    # =========================

    save_password(
        password,
        "analyzed"
    )


    # =========================
    # FINAL RESULT
    # =========================

    return render_template(

        "index.html",

        strength=strength,

        score=score,

        password_length=length,

        breach_result=breach_result,

        suggestions=suggestions,

        common_password=common_password,

        password_reused=password_reused,

        password_expired=password_expired,

        expiry_date=expiry_date,

        zxcvbn_score=zxcvbn_score,

        zxcvbn_guesses=zxcvbn_guesses,

        zxcvbn_crack_time=zxcvbn_crack_time

    )


# =========================
# START FLASK SERVER
# =========================

if __name__ == "__main__":

  app.run(
    host="0.0.0.0",
    port=5000,
    debug=True
)