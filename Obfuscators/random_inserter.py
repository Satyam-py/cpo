import random
import string

def random_insert_obfuscate(payload):
    result = ""

    for char in payload:
        random_char = random.choice(
            string.ascii_letters
        )
        result += char + random_char
    return result

def random_insert_deobfuscate(payload):

    return payload[::2]