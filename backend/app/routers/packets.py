from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import or_
from typing import Optional
import math
from app.database import get_db
from app.models import PacketLog
from app.schemas import PacketLogResponse, PaginatedPacketLogs, PacketIngestRequest
from app.services.simulator import simulator

router = APIRouter(prefix="/api/packets", tags=["Packet Logs"])

@router.get("", response_model=PaginatedPacketLogs)
def get_packet_logs(
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=200),
    search: Optional[str] = None,
    action: Optional[str] = None,
    protocol: Optional[str] = None,
    is_simulated: Optional[bool] = None,
    db: Session = Depends(get_db)
):
    query = db.query(PacketLog)

    if action:
        query = query.filter(PacketLog.action == action.upper())
    if protocol:
        query = query.filter(PacketLog.protocol == protocol.upper())
    if is_simulated is not None:
        query = query.filter(PacketLog.is_simulated == is_simulated)

    if search:
        search_term = f"%{search}%"
        query = query.filter(
            or_(
                PacketLog.src_ip.like(search_term),
                PacketLog.dst_ip.like(search_term),
                PacketLog.decision_reason.like(search_term),
                PacketLog.raw_summary.like(search_term)
            )
        )

    total = query.count()
    total_pages = math.ceil(total / page_size) if total > 0 else 1
    offset = (page - 1) * page_size

    items = query.order_by(PacketLog.timestamp.desc(), PacketLog.id.desc()).offset(offset).limit(page_size).all()

    return PaginatedPacketLogs(
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
        items=items
    )

@router.get("/{packet_id}", response_model=PacketLogResponse)
def get_packet_detail(packet_id: int, db: Session = Depends(get_db)):
    packet = db.query(PacketLog).filter(PacketLog.id == packet_id).first()
    if not packet:
        raise HTTPException(status_code=404, detail="Packet log not found")
    return packet

@router.post("/ingest", response_model=PacketLogResponse, status_code=201)
def ingest_packet(
    packet_in: PacketIngestRequest,
    db: Session = Depends(get_db)
):
    pkt_data = packet_in.model_dump()
    pkt_data["raw_summary"] = f"Ingested {packet_in.protocol} {packet_in.src_ip} -> {packet_in.dst_ip}"
    log = simulator.process_packet_data(pkt_data, db)
    return log

@router.delete("/clear")
def clear_packet_logs(db: Session = Depends(get_db)):
    count = db.query(PacketLog).delete()
    db.commit()
    return {"status": "success", "deleted_count": count}
