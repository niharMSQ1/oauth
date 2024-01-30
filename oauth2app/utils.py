import base64
import os

def generate_base64_string():
    binary_data = os.urandom(32)
    base64_string = base64.b64encode(binary_data).decode('utf-8')

    return base64_string