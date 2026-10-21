"""Calls a helper program found through PATH."""

import subprocess

subprocess.run(["greet"], check=True)
