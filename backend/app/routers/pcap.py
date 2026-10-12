import os
import shutil
import tempfile
from fastapi import APIRouter, UploadFile, File, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import Dict, Any
from app.database import get_db
from app.services.pcap_service import PcapService

router = APIRouter(prefix="/api/pcap", tags=["PCAP Offline Ingestion"])

SAMPLE_PCAP_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "sample_captures", "sample_traffic.pcap")

@router.post("/upload")
async def upload_pcap(
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    if not (file.filename.endswith(".pcap") or file.filename.endswith(".pcapng") or file.filename.endswith(".cap")):
        raise HTTPException(status_code=400, detail="Only .pcap, .pcapng, and .cap files are supported.")

    with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
        shutil.copyfileobj(file.file, tmp)
        tmp_path = tmp.name

    try:
        results = PcapService.process_pcap_file(tmp_path, db)
        results["filename"] = file.filename
        return results
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error analyzing PCAP file: {str(e)}")
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)

@router.post("/sample")
def analyze_sample_capture(db: Session = Depends(get_db)):
    """Generates and analyzes the built-in sample PCAP capture with Scapy."""
    os.makedirs(os.path.dirname(SAMPLE_PCAP_PATH), exist_ok=True)
    if not os.path.exists(SAMPLE_PCAP_PATH):
        PcapService.generate_sample_pcap(SAMPLE_PCAP_PATH)

    results = PcapService.process_pcap_file(SAMPLE_PCAP_PATH, db)
    results["filename"] = "sample_traffic.pcap"
    return results

@router.get("/sample-info")
def get_sample_info():
    exists = os.path.exists(SAMPLE_PCAP_PATH)
    size = os.path.getsize(SAMPLE_PCAP_PATH) if exists else 0
    return {
        "sample_available": exists,
        "sample_path": SAMPLE_PCAP_PATH,
        "size_bytes": size
    }
