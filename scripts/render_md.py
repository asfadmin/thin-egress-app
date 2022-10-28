import argparse
from pathlib import Path
from typing import Optional

import markdown


def render_markdown(inpath: Path, outpath: Optional[Path] = None):
    rendered = markdown.markdown(
        inpath.read_text(),
        extensions=[
            "markdown.extensions.sane_lists",
            "markdown.extensions.tables",
            "pymdownx.betterem",
            "pymdownx.highlight",
            "pymdownx.superfences",
        ]
    )
    outpath = outpath or inpath.with_suffix(".html")
    outpath.write_text(rendered)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("--output", "-o", type=Path)

    args = parser.parse_args()

    render_markdown(args.input, args.output)


if __name__ == "__main__":
    main()
