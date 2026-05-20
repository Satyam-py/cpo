import re


def split_strings(payload):

    keywords = [
        "powershell",
        "cmd",
        "whoami",
        "system",
        "socket",
        "subprocess"
    ]

    result = payload

    for word in keywords:

        middle = len(word) // 2

        first = word[:middle]
        second = word[middle:]

        split_word = f'"{first}" + "{second}"'

        result = result.replace(word, split_word)

    return result


def unsplit_strings(payload):

    pattern = r'"(.*?)"\s*\+\s*"(.*?)"'

    matches = re.findall(pattern, payload)

    result = payload

    for first, second in matches:

        combined = first + second

        split_version = f'"{first}" + "{second}"'

        result = result.replace(
            split_version,
            combined
        )

    return result