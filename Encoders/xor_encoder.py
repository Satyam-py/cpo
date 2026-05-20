def xor_encode(payload, key):

    encoded = ""

    for char in payload:

        encoded += chr(ord(char) ^ key)

    return encoded


def xor_decode(encoded_payload, key):

    decoded = ""

    for char in encoded_payload:

        decoded += chr(ord(char) ^ key)

    return decoded