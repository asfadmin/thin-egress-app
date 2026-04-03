import argparse
import json
import tkinter as tk
import traceback

import yaml
from rain_api_core.bucket_map import BucketMap


def main(args=None):
    parser = get_parser()

    parsed_args = parser.parse_args(args)
    handle_args(parsed_args)


def get_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()

    configure_parser(parser)

    return parser


def configure_parser(parser: argparse.ArgumentParser):
    pass


def handle_args(args: argparse.Namespace):
    policy_sandbox()


def policy_sandbox():
    window = tk.Tk()
    window.title("IAM Policy Generator Sandbox")
    window.columnconfigure(0, weight=1)
    window.rowconfigure(0, weight=1)

    frm_content = tk.Frame(window)
    frm_content.columnconfigure(0, weight=1)
    frm_content.columnconfigure(1, weight=1)
    frm_content.rowconfigure(1, weight=1)
    frm_content.grid(row=0, column=0, sticky="nsew")

    def handle_text():
        text = txt_bucketmap.get("1.0", tk.END).strip()
        try:
            groups = yaml.safe_load(var_group.get())
            if not text:
                bucket_map = {}
            else:
                bucket_map = yaml.safe_load(text)
            b_map = BucketMap(bucket_map)

            policy = b_map.to_iam_policy(groups)
            policy_text = json.dumps(policy, indent=2)
            txt_policy.delete("1.0", tk.END)
            txt_policy.insert(tk.END, policy_text)

            minified_policy_text = json.dumps(policy, separators=(":", ","))
            var_size.set(str(len(minified_policy_text)))
        except Exception:
            exc_text = traceback.format_exc()
            txt_policy.delete("1.0", tk.END)
            txt_policy.insert(tk.END, exc_text)
            var_size.set("0")

    # Bucket map panel
    tk.Label(frm_content, text="Bucket map YAML").grid(row=0, column=0)

    txt_bucketmap = tk.Text(frm_content)
    txt_bucketmap.bind("<Key>", lambda _: window.after(1, handle_text))
    txt_bucketmap.grid(row=1, column=0, sticky="nsew")

    # Policy panel
    tk.Label(frm_content, text="Policy JSON").grid(row=0, column=1)

    txt_policy = tk.Text(frm_content)
    txt_policy.grid(row=1, column=1, sticky="nsew")

    # Group selector
    frm_groups = tk.Frame(frm_content)
    frm_groups.grid(row=2, column=0)

    tk.Label(frm_groups, text="User Groups: ").grid(row=0, column=0)
    var_group = tk.StringVar(value="null")
    entry_groups = tk.Entry(frm_groups, textvariable=var_group)
    entry_groups.bind("<Key>", lambda _: window.after(1, handle_text))
    entry_groups.grid(row=0, column=1)

    # Minified size indicator
    frm_size = tk.Frame(frm_content)
    frm_size.grid(row=2, column=1)

    tk.Label(frm_size, text="Minified Size: ").grid(row=0, column=0)

    var_size = tk.StringVar(value="0")
    tk.Label(frm_size, textvariable=var_size).grid(row=0, column=1)

    tk.Label(frm_size, text=" (max 2048)").grid(row=0, column=2)

    handle_text()
    window.mainloop()
