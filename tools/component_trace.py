"""Print component states for comparison with another group's implementation."""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from saes import trace_encrypt


def main():
    parser = argparse.ArgumentParser(description="S-AES 逐组件加密状态（四位 Hex）")
    parser.add_argument("plaintext", help="16 位明文，如 1234")
    parser.add_argument("key", help="16 位密钥，如 2D55")
    args = parser.parse_args()
    if len(args.plaintext) != 4 or len(args.key) != 4:
        parser.error("明文和密钥都必须是四位十六进制数")
    try:
        values = trace_encrypt(int(args.plaintext, 16), int(args.key, 16))
    except ValueError as error:
        parser.error(str(error))
    for stage, value in values.items():
        print(f"{stage:12s} {value:04X}")


if __name__ == "__main__":
    main()
