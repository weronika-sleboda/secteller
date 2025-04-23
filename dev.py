"""
Runs the scripts that starts Django server
"""

import subprocess


def run_server():
    """
    Run script in a subprocess
    """
    command = ["poetry", "run", "python", "manage.py", "runserver"]
    subprocess.run(command, check=True)

if __name__ == "__main__":
    run_server()
