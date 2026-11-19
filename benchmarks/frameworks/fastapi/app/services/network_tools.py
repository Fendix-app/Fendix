import subprocess


def ping(host: str) -> str:
    result = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True, text=True)  # EVAL-SINK
    return result.stdout
