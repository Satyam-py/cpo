def escape_obfuscate(payload):

    result = ""

    for char in payload:

        result += "\\x" + format(ord(char), "02x")

    return result


def escape_deobfuscate(payload):

    return bytes.fromhex(
        payload.replace("\\x", "")
    ).decode("utf-8")