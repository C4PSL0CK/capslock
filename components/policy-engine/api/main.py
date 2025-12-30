from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Dict
from datetime import datetime

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
    return [
        {
            "name": "dev-test",
            "environment": "dev",
            "securityLevel": "low",
            "riskTolerance": "high",
            "compliance": [],
            "labels": {"environment": "dev", "security-level": "low"},
            "confidence": 0.95,
            "detectedAt": datetime.now().isoformat()
        },
        {
            "name": "staging-test",
            "environment": "staging",
            "securityLevel": "medium",
            "riskTolerance": "medium",
            "compliance": ["iso27001", "soc2"],
            "labels": {
                "environment": "staging",
                "security-level": "medium",
                "compliance-iso27001": "true",
                "compliance-soc2": "true"
            },
            "confidence": 0.92,
            "detectedAt": datetime.now().isoformat()
        },
        {
            "name": "prod-test",
            "environment": "prod",
            "securityLevel": "high",
            "riskTolerance": "low",
            "compliance": ["iso27001", "soc2", "pci-dss", "cis"],
            "labels": {
                "environment": "prod",
                "security-level": "high",
                "compliance-iso27001": "true",
                "compliance-soc2": "true",
                "compliance-pci-dss": "true",
                "compliance-cis": "true"
            },
            "confidence": 0.98,
            "detectedAt": datetime.now().isoformat()
        }
    ]

@app.get("/api/dashboard/stats", response_model=DashboardStats)
async def dashboard_stats():
    return {
        "totalNamespaces": 7,
        "devNamespaces": 1,
        "stagingNamespaces": 1,
        "prodNamespaces": 1,
        "complianceEnabled": 2,
        "lastScanTime": datetime.now().isoformat()
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
