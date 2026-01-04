from fastapi import FastAPI
import subprocess
import os

app = FastAPI()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DR_DIR = os.path.join(BASE_DIR, "dr-files")

@app.get("/")
def health():
    return {"status": "controller alive"}

@app.post("/set-version/{version}")
def set_version(version: str):
    filename = f"dr-{version}.yaml"
    path = os.path.join(DR_DIR, filename)

    if not os.path.exists(path):
        return {"error": "invalid version"}

    result = subprocess.run(
        ["kubectl", "apply", "-f", path],
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        return {"error": result.stderr}

    return {"status": "ok", "applied": path}

