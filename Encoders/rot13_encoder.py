import codecs
def rot13_encode(payload):
    return codecs.encode(payload, "rot_13")

def rot13_decode(encoded_payload):
    return codecs.decode(encoded_payload, "rot_13")