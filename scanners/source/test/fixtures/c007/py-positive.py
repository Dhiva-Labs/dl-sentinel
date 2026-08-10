import random


def generate_otp():
    # One-time password (OTP) sent to the user's phone.
    return random.randint(100000, 999999)
