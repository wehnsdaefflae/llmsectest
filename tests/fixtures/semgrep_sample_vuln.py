"""Deliberately vulnerable sample: input for the committed Semgrep fixture."""

import subprocess

API_KEY = "sk-not-a-real-key-0000"


def run_report(name):
    subprocess.run(f"generate --for {name}", shell=True)


def evaluate(expr):
    return eval(expr)
