import base64
def base64_encode(payload):

    """
    Encodes the given payload using Base64.
    """

    # Convert string to bytes
    payload_bytes = payload.encode("utf-8")

    # Perform Base64 encoding
    encoded_bytes = base64.b64encode(payload_bytes)

    # Convert bytes back to string
    encoded_payload = encoded_bytes.decode("utf-8")

    return encoded_payload

def base64_decode(encoded_payload):

    """
    Decodes a Base64 encoded payload.
    """

    # Convert encoded string to bytes
    encoded_bytes = encoded_payload.encode("utf-8")

    # Decode Base64
    decoded_bytes = base64.b64decode(encoded_bytes)

    # Convert bytes back to string
    decoded_payload = decoded_bytes.decode("utf-8")

    return decoded_payload