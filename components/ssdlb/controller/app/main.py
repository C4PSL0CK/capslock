from fastapi import FastAPI
from pydantic import BaseModel
import subprocess
import os

app = FastAPI()

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DR_DIR = os.path.join(BASE_DIR, "dr-files")


@app.get("/")
def health():
    return {"status": "controller alive"}


class VersionRequest(BaseModel):
    version: str


def apply_yaml(file_path: str):
    result = subprocess.run(
        ["kubectl", "apply", "-f", file_path],
        capture_output=True,
        text=True
    )
    if result.returncode != 0:
        return False, result.stderr.strip()
    return True, result.stdout.strip()


@app.post("/set-version/{version}")
def set_version(version: str):
    file_name = f"dr-{version}.yaml"
    file_path = os.path.join(DR_DIR, file_name)

    if not os.path.exists(file_path):
        return {"error": f"DR file not found: {file_path}"}

    ok, out = apply_yaml(file_path)
    if not ok:
        return {"error": "Failed to apply DR file", "details": out}

    return {"status": "ok", "applied": file_path, "kubectl": out}
