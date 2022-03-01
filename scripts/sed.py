import argparse
import re


def main(pattern, replacement, path_in, path_out):
    # For code simplicity, always copy the whole string to memory
    with open(path_in) as f:
        contents = f.read()

    new_contents = re.sub(pattern, replacement, contents)

    with open(path_out, "w") as f:
        f.write(new_contents)


def substitute(pattern, replacement, buf_in, buf_out):
    for line in buf_in:
        buf_out.write(re.sub(pattern, replacement, line))


def pattern(arg):
    try:
        return re.compile(arg, flags=re.MULTILINE)
    except re.error:
        raise ValueError()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("pattern", help="Regular expression to search for", type=pattern)
    parser.add_argument("replacement", help="Text to substitute")
    parser.add_argument(
        "-i", "--infile",
        help="Input file to read from",
        required=True
    )
    parser.add_argument(
        "-o", "--outfile",
        help="Input file to read from",
        default=None
    )

    args = parser.parse_args()

    path_in = args.infile
    path_out = args.outfile or path_in
    main(args.pattern, args.replacement, path_in, path_out)
