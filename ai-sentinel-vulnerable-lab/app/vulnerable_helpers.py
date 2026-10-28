"""Risky helpers are inert unless explicitly called by local demonstrations."""
import hashlib
import os
import pickle
import subprocess
from pathlib import Path
import yaml

FAKE_API_KEY = "FAKE_DEMO_KEY_DO_NOT_USE_000000000000"


# INTENTIONALLY VULNERABLE — FOR AUTHORIZED LOCAL TESTING ONLY
def load_untrusted_pickle(payload: bytes):
    """Unsafe deserialization example. Never pass attacker-controlled bytes."""
    return pickle.loads(payload)


# INTENTIONALLY VULNERABLE — FOR AUTHORIZED LOCAL TESTING ONLY
def load_untrusted_yaml(payload: str):
    """Unsafe YAML load example. Callers must not supply untrusted YAML."""
    return yaml.load(payload, Loader=yaml.Loader)


# INTENTIONALLY VULNERABLE — FOR AUTHORIZED LOCAL TESTING ONLY
def run_local_demo_command(user_input: str):
    """Shell interpretation is the risky pattern; this is never invoked at startup."""
    return subprocess.run("echo " + user_input, shell=True, capture_output=True, text=True)


# INTENTIONALLY VULNERABLE — FOR AUTHORIZED LOCAL TESTING ONLY
def read_demo_path(base_dir: str, user_path: str) -> str:
    """Join without containment validation; reads only when called by a test."""
    target = os.path.join(base_dir, user_path)
    return Path(target).read_text(encoding="utf-8")


# INTENTIONALLY VULNERABLE — FOR AUTHORIZED LOCAL TESTING ONLY
def password_digest(password: str) -> str:
    """MD5 is unsuitable for password storage; this is a scanner fixture."""
    return hashlib.md5(password.encode()).hexdigest()
