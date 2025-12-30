from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Dict
from datetime import datetime
import subprocess
import os

app = FastAPI(title="EAPE API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class NamespaceInfo(BaseModel):
    name: str
    environment: str
    securityLevel: str
    riskTolerance: str
    compliance: List[str]
    labels: Dict[str, str]
    confidence: float
    detectedAt: str

class DashboardStats(BaseModel):
    totalNamespaces: int
    devNamespaces: int
    stagingNamespaces: int
    prodNamespaces: int
    complianceEnabled: int
    lastScanTime: str

@app.get("/")
async def root():
    return {
        "service": "EAPE API",
        "version": "1.0.0",
        "status": "running"
    }

@app.get("/api/health")
async def health():
    return {"status": "healthy"}

@app.get("/api/namespaces", response_model=List[NamespaceInfo])
async def list_namespaces():
    """
    List all namespaces with environment detection from Go backend
    """
    try:
        # Get the path to the Go binary
        script_dir = os.path.dirname(os.path.abspath(__file__))
        binary_path = os.path.join(script_dir, "..", "bin", "policy-engine")
        
        # Call Go backend
        result = subprocess.run(
            [binary_path, "detect-json"],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode == 0:
            # Parse JSON output from Go
            import json
            namespaces_data = json.loads(result.stdout)
            
            # Filter out system namespaces for cleaner display
            filtered = [
                ns for ns in namespaces_data 
                if not ns['name'].startswith('kube-') 
                and ns['name'] not in ['default', 'gatekeeper-system']
            ]
            
            return filtered
        else:
            print(f"Go binary error: {result.stderr}")
            # Fallback to empty list
            return []
            
    except Exception as e:
        print(f"Error calling Go backend: {e}")
        # Fallback to empty list
        return []

@app.get("/api/dashboard/stats", response_model=DashboardStats)
async def dashboard_stats():
    """
    Get dashboard statistics from real namespace data
    """
    try:
        # Get namespace data
        namespaces = await list_namespaces()
        
        # Count by environment
        total = len(namespaces)
        dev_count = sum(1 for ns in namespaces if ns.get('environment') == 'dev')
        staging_count = sum(1 for ns in namespaces if ns.get('environment') == 'staging')
        prod_count = sum(1 for ns in namespaces if ns.get('environment') == 'prod')
        compliance_count = sum(1 for ns in namespaces if len(ns.get('compliance', [])) > 0)
        
        return {
            "totalNamespaces": total,
            "devNamespaces": dev_count,
            "stagingNamespaces": staging_count,
            "prodNamespaces": prod_count,
            "complianceEnabled": compliance_count,
            "lastScanTime": datetime.now().isoformat()
        }
    except Exception as e:
        print(f"Error getting stats: {e}")
        return {
            "totalNamespaces": 0,
            "devNamespaces": 0,
            "stagingNamespaces": 0,
            "prodNamespaces": 0,
            "complianceEnabled": 0,
            "lastScanTime": datetime.now().isoformat()
        }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
