import os
import subprocess

def run(cmd: str) -> None:
    subprocess.call(cmd, shell=True)  # a sink the AST analyzer reports

API_KEY = os.environ.get("API_KEY", "")
