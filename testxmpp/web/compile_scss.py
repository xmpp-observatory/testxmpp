import argparse

import sass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-o", "--output", required=True)
    parser.add_argument("source")
    args = parser.parse_args()

    css = sass.compile(
        filename=args.source,
        include_paths=["testxmpp/web/scss"],
        output_style="expanded",
    )
    with open(args.output, "w", encoding="utf-8") as output:
        output.write(css)


if __name__ == "__main__":
    main()
