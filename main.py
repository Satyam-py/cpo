import argparse
from pathlib import Path
from datetime import datetime

from colorama import Fore, init

from cpo import settings # type: ignore

from cpo.Encoders.base64_encoder import *# type: ignore
from cpo.Encoders.xor_encoder import *# type: ignore
from cpo.Encoders.rot13_encoder import *# type: ignore

from cpo.Obfuscators.string_splitter import *# type: ignore
from cpo.Obfuscators.escape_obfuscator import *# type: ignore
from cpo.Obfuscators.reverse_obfuscator import *# type: ignore
from cpo.Obfuscators.random_inserter import *# type: ignore

from cpo.Detector.detector import *# type: ignore

init(autoreset=True)

# =====================================================
# AUTO CREATE DIRECTORIES
# =====================================================




# =====================================================
# COLOR OUTPUT
# =====================================================

def success(msg):

    print(Fore.GREEN + msg)


def error(msg):

    print(Fore.RED + msg)


def warning(msg):

    print(Fore.YELLOW + msg)


def info(msg):

    print(Fore.CYAN + msg)


# =====================================================
# FILE FUNCTIONS
# =====================================================

def load_file(path):

    try:

        with open(path, "r", encoding="utf-8") as file:

            return file.read()

    except Exception as e:

        error(f"\n[!] Error loading file: {e}")
        return None


def save_file(folder, name, content):

    folder = Path(folder)

    folder.mkdir(
        parents=True,
        exist_ok=True
    )

    path = folder / name

    with open(path, "w", encoding="utf-8") as file:

        file.write(content)

    success(f"\n[+] Saved: {path}")


def generate_report_name():

    timestamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )

    return f"report_{timestamp}.txt"


# =====================================================
# ENCODERS
# =====================================================

encoders = {

    "base64": (
        base64_encode,# type: ignore
        base64_decode# type: ignore
    ),

    "xor": (
        xor_encode,# type: ignore
        xor_decode# type: ignore
    ),

    "rot13": (
        rot13_encode,# type: ignore
        rot13_decode# type: ignore
    )
}


# =====================================================
# OBFUSCATORS
# =====================================================

obfuscators = {

    "split": (
        split_strings, # type: ignore
        unsplit_strings # type: ignore
    ),

    "escape": (
        escape_obfuscate,# type: ignore
        escape_deobfuscate# type: ignore
    ),

    "reverse": (
        reverse_obfuscate,# type: ignore
        reverse_deobfuscate# type: ignore
    ),

    "random": (
        random_insert_obfuscate,# type: ignore
        random_insert_deobfuscate# type: ignore
    )
} 


# =====================================================
# ARGPARSE
# =====================================================

parser = argparse.ArgumentParser(

    prog="cpo",

    description=
    "CPO - Custom Payload Obfuscator"
)

print(settings.BANNER)

parser.add_argument(

    "--version",

    action="version",

    version=f"CPO v{settings.VERSION}"
)

subparsers = parser.add_subparsers(

    dest="command"
)


# =====================================================
# ENCODE
# =====================================================

encode_parser = subparsers.add_parser(

    "encode",

    help="Encode payload"
)

encode_parser.add_argument(

    "-f",
    "--file",

    required=True,

    help="Input payload file"
)

encode_parser.add_argument(

    "-m",
    "--method",

    required=True,

    choices=encoders.keys(),

    help="Encoding method"
)

encode_parser.add_argument(

    "-k",
    "--key",

    type=int,

    help="XOR key"
)

encode_parser.add_argument(

    "-o",
    "--output",

    help="Output file name"
)


# =====================================================
# DECODE
# =====================================================

decode_parser = subparsers.add_parser(

    "decode",

    help="Decode payload"
)

decode_parser.add_argument(

    "-f",
    "--file",

    required=True,

    help="Encoded payload file"
)

decode_parser.add_argument(

    "-m",
    "--method",

    required=True,

    choices=encoders.keys(),

    help="Decoding method"
)

decode_parser.add_argument(

    "-k",
    "--key",

    type=int,

    help="XOR key"
)

decode_parser.add_argument(

    "-o",
    "--output",

    help="Output file name"
)


# =====================================================
# OBFUSCATE
# =====================================================

obf_parser = subparsers.add_parser(

    "obfuscate",

    help="Obfuscate payload"
)

obf_parser.add_argument(

    "-f",
    "--file",

    required=True,

    help="Input payload file"
)

obf_parser.add_argument(

    "-m",
    "--method",

    required=True,

    choices=obfuscators.keys(),

    help="Obfuscation method"
)

obf_parser.add_argument(

    "-o",
    "--output",

    help="Output file name"
)


# =====================================================
# DEOBFUSCATE
# =====================================================

deobf_parser = subparsers.add_parser(

    "deobfuscate",

    help="Deobfuscate payload"
)

deobf_parser.add_argument(

    "-f",
    "--file",

    required=True,

    help="Obfuscated payload file"
)

deobf_parser.add_argument(

    "-m",
    "--method",

    required=True,

    choices=obfuscators.keys(),

    help="Deobfuscation method"
)

deobf_parser.add_argument(

    "-o",
    "--output",

    help="Output file name"
)


# =====================================================
# DETECT
# =====================================================

detect_parser = subparsers.add_parser(

    "detect",

    help="Run comparative detection"
)

detect_parser.add_argument(

    "-o",
    "--original",

    required=True,

    help="Original payload file"
)

detect_parser.add_argument(

    "-b",
    "--obfuscated",

    required=True,

    help="Obfuscated payload file"
)

detect_parser.add_argument(

    "-e",
    "--encoded",

    required=True,

    help="Encoded payload file"
)

detect_parser.add_argument(

    "-r",
    "--report",

    help="Report file name"
)


# =====================================================
# MAIN
# =====================================================

def main():

    args = parser.parse_args()
    directories = [

        settings.ENCODED_DIR,
        settings.DECODED_DIR,

        settings.OBFUSCATED_DIR,
        settings.DEOBFUSCATED_DIR,

        settings.REPORT_DIR
    ]

    if settings.AUTO_CREATE_DIRECTORIES:

        for directory in directories:

            Path(directory).mkdir(
                parents=True,
                exist_ok=True
            )
    # =================================================
    # ENCODE
    # =================================================

    if args.command == "encode":

        payload = load_file(args.file)

        if not payload:
            exit()

        encode_func = encoders[args.method][0]

        if args.method == "xor":

            if args.key is None:

                error("\n[!] XOR requires --key")
                exit()

            result = encode_func(
                payload,
                args.key
            )

        else:

            result = encode_func(payload)

        info("\n========== ENCODED ==========\n")
        print(result)

        output_name = (
            args.output
            or f"{args.method}_encoded.txt"
        )

        save_file(
            settings.ENCODED_DIR,
            output_name,
            result
        )

    # =================================================
    # DECODE
    # =================================================

    elif args.command == "decode":

        payload = load_file(args.file)

        if not payload:
            exit()

        decode_func = encoders[args.method][1]

        if args.method == "xor":

            if args.key is None:

                error("\n[!] XOR requires --key")
                exit()

            result = decode_func(
                payload,
                args.key
            )

        else:

            result = decode_func(payload)

        info("\n========== DECODED ==========\n")
        print(result)

        output_name = (
            args.output
            or f"{args.method}_decoded.txt"
        )

        save_file(
            settings.DECODED_DIR,
            output_name,
            result
        )

    # =================================================
    # OBFUSCATE
    # =================================================

    elif args.command == "obfuscate":

        payload = load_file(args.file)

        if not payload:
            exit()

        obfuscate_func = obfuscators[
            args.method
        ][0]

        result = obfuscate_func(payload)

        info("\n========== OBFUSCATED ==========\n")
        print(result)

        output_name = (
            args.output
            or f"{args.method}_obfuscated.txt"
        )

        save_file(
            settings.OBFUSCATED_DIR,
            output_name,
            result
        )

    # =================================================
    # DEOBFUSCATE
    # =================================================

    elif args.command == "deobfuscate":

        payload = load_file(args.file)

        if not payload:
            exit()

        deobfuscate_func = obfuscators[
            args.method
        ][1]

        result = deobfuscate_func(payload)

        info("\n========== DEOBFUSCATED ==========\n")
        print(result)

        output_name = (
            args.output
            or f"{args.method}_deobfuscated.txt"
        )

        save_file(
            settings.DEOBFUSCATED_DIR,
            output_name,
            result
        )

    # =================================================
    # DETECT
    # =================================================

    elif args.command == "detect":

        original_payload = load_file(
            args.original
        )

        obfuscated_payload = load_file(
            args.obfuscated
        )

        encoded_payload = load_file(
            args.encoded
        )

        if (
            not original_payload
            or not obfuscated_payload
            or not encoded_payload
        ):

            exit()

        results = compare_payloads( # type: ignore

            original_payload,

            obfuscated_payload,

            encoded_payload
        ) 

        report = generate_comparison_report( # type: ignore
            results
        )

        print("\n")
        print(report)

        report_name = (
            args.report
            or generate_report_name()
        )

        save_file(
            settings.REPORT_DIR,
            report_name,
            report
        )

    # =================================================
    # NO ARGUMENTS
    # =================================================

    else:

        parser.print_help()


if __name__ == "__main__":

    main()