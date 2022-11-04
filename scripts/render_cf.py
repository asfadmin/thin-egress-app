import argparse
from pathlib import Path
from typing import Optional

import jinja2


def render_templates(
    inpath: Path,
    outpath: Optional[Path] = None,
    template_args: dict = {}
):
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader("./"),
        autoescape=False,
        undefined=jinja2.StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
    )

    template = env.get_template(str(inpath))

    output = template.render(**template_args)

    outpath = outpath or inpath.with_suffix("")
    outpath.write_text(output)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("--output", "-o", type=Path)
    parser.add_argument("--code-bucket")
    parser.add_argument("--dependency-archive-key")
    parser.add_argument("--code-archive-key")
    parser.add_argument("--build-version")
    parser.add_argument("--description")

    args = parser.parse_args()

    template_args = {
        k: v
        for k, v in vars(args).items()
        if k not in ("input", "output")
    }
    render_templates(args.input, args.output, template_args)


if __name__ == "__main__":
    main()
