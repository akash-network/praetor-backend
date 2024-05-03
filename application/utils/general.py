import string
from random import choice


def generate_random_string(length: int = 15):
    # Generate a random string of letters and digits.
    letters_and_digits = string.ascii_lowercase + string.digits
    return ''.join(choice(letters_and_digits) for i in range(length))


def success_response(data):
    response = {
        "status": "success",
        "data": data
    }
    return response


def error_response(code: str, message):
    response = {
        "status": "error",
        "error": {
            "error_code": code,
            "message": message
        }
    }
    return response
