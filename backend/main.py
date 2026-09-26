"""FastAPI backend: REST + WebSocket + PostgreSQL. Run: uvicorn backend.main:app --reload"""
import asyncio
import os
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Literal, Optional

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from psycopg_pool import ConnectionPool
from pydantic import BaseModel

from backend import mock_data

load_dotenv()
DSN = (f"host={os.getenv('DB_HOST', 'localhost')} port={os.getenv('DB_PORT', '5432')} "
       f"dbname={os.getenv('DB_NAME', 'nta')} user={os.getenv('DB_USER', 'nta')} "
       f"password={os.getenv('DB_PASSWORD', 'nta_pass')}")
pool = ConnectionPool(DSN, kwargs={"row_factory": dict_row}, open=False)


# ---------- contract (must match README) ----------
class Talker(BaseModel):
    ip: str
    packets: int
    bytes: int


class PortCount(BaseModel):
    port: int
    packets: int


class StatsWindow(BaseModel):
    window_start: datetime
    window_end: datetime
    packets_per_sec: float
    bytes_per_sec: float
    protocol_counts: dict[str, int]
    top_talkers: list[Talker]
    top_ports: list[PortCount]


class Alert(BaseModel):
    timestamp: datetime
    type: Literal["port_scan", "syn_flood", "traffic_spike", "arp_spoofing", "dns_anomaly"]
    severity: Literal["low", "medium", "high"]
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    description: str
    evidence: dict = {}


class IngestBundle(BaseModel):
    stats: Optional[StatsWindow] = None
    alerts: list[Alert] = []


class ReplayRequest(BaseModel):
    scenario: str = "mixed"
    speed: float = 5.0  # 1.0 = real time (5 s per window); 5.0 = 1 s per window


# ---------- websocket hub ----------
class Hub:
    def __init__(self):
        self.clients: set[WebSocket] = set()

    async def broadcast(self, msg: dict):
        dead = []
        for ws in self.clients:
            try:
                await ws.send_json(msg)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.clients.discard(ws)


hub = Hub()
replay_task: Optional[asyncio.Task] = None


# ---------- storage ----------
def save_stats(s: StatsWindow):
    with pool.connection() as c:
        c.execute(
            "INSERT INTO stats_windows (window_start, window_end, packets_per_sec, bytes_per_sec,"
            " protocol_counts, top_talkers, top_ports) VALUES (%s,%s,%s,%s,%s,%s,%s)",
            (s.window_start, s.window_end, s.packets_per_sec, s.bytes_per_sec,
             Jsonb(s.protocol_counts), Jsonb([t.model_dump() for t in s.top_talkers]),
             Jsonb([p.model_dump() for p in s.top_ports])))


def save_alert(a: Alert) -> int:
    with pool.connection() as c:
        row = c.execute(
            "INSERT INTO alerts (ts, type, severity, src_ip, dst_ip, description, evidence)"
            " VALUES (%s,%s,%s,%s,%s,%s,%s) RETURNING id",
            (a.timestamp, a.type, a.severity, a.src_ip, a.dst_ip, a.description,
             Jsonb(a.evidence))).fetchone()
    return row["id"]


async def process(bundle: IngestBundle):
    """Store a window and push it to every connected dashboard."""
    if bundle.stats:
        await asyncio.to_thread(save_stats, bundle.stats)
        await hub.broadcast({"type": "stats", "data": bundle.stats.model_dump(mode="json")})
    for a in bundle.alerts:
        aid = await asyncio.to_thread(save_alert, a)
        await hub.broadcast({"type": "alert", "data": {"id": aid, **a.model_dump(mode="json")}})


async def run_replay(scenario: str, speed: float):
    for stats, alerts in mock_data.generate(scenario):
        await process(IngestBundle(stats=StatsWindow(**stats), alerts=[Alert(**a) for a in alerts]))
        await asyncio.sleep(mock_data.WINDOW_S / speed)
    await hub.broadcast({"type": "replay_done", "data": {"scenario": scenario}})


# ---------- app ----------
@asynccontextmanager
async def lifespan(app: FastAPI):
    pool.open()
    yield
    pool.close()


app = FastAPI(title="Network Traffic Analyzer", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


@app.get("/api/health")
def health():
    with pool.connection() as c:
        c.execute("SELECT 1")
    return {"status": "ok"}


@app.post("/api/ingest")
async def ingest(bundle: IngestBundle):
    """Engine posts one window (stats + any alerts) here."""
    await process(bundle)
    return {"stored": True}


@app.get("/api/stats")
def get_stats(start: Optional[datetime] = None, end: Optional[datetime] = None,
              ip: Optional[str] = None, limit: int = Query(500, le=5000)):
    q, p = "SELECT * FROM stats_windows WHERE TRUE", []
    if start:
        q += " AND window_start >= %s"; p.append(start)
    if end:
        q += " AND window_end <= %s"; p.append(end)
    if ip:
        q += " AND top_talkers @> %s"; p.append(Jsonb([{"ip": ip}]))
    q += " ORDER BY window_start DESC LIMIT %s"; p.append(limit)
    with pool.connection() as c:
        rows = c.execute(q, p).fetchall()
    return list(reversed(rows))


@app.get("/api/alerts")
def get_alerts(start: Optional[datetime] = None, end: Optional[datetime] = None,
               ip: Optional[str] = None, type: Optional[str] = None,
               limit: int = Query(200, le=2000)):
    q = ("SELECT id, ts AS timestamp, type, severity, src_ip::text AS src_ip,"
         " dst_ip::text AS dst_ip, description, evidence FROM alerts WHERE TRUE")
    p = []
    if start:
        q += " AND ts >= %s"; p.append(start)
    if end:
        q += " AND ts <= %s"; p.append(end)
    if ip:
        q += " AND (src_ip = %s OR dst_ip = %s)"; p += [ip, ip]
    if type:
        q += " AND type = %s"; p.append(type)
    q += " ORDER BY ts DESC LIMIT %s"; p.append(limit)
    with pool.connection() as c:
        return c.execute(q, p).fetchall()


@app.post("/api/replay")
async def replay(req: ReplayRequest):
    global replay_task
    if req.scenario not in mock_data.SCENARIOS:
        raise HTTPException(400, f"scenario must be one of {list(mock_data.SCENARIOS)}")
    if replay_task and not replay_task.done():
        raise HTTPException(409, "a replay is already running")
    replay_task = asyncio.create_task(run_replay(req.scenario, req.speed))
    return {"started": req.scenario, "speed": req.speed}


@app.delete("/api/data")
def clear_data():
    with pool.connection() as c:
        c.execute("TRUNCATE stats_windows, alerts RESTART IDENTITY")
    return {"cleared": True}


@app.websocket("/ws/live")
async def live(ws: WebSocket):
    await ws.accept()
    hub.clients.add(ws)
    try:
        while True:
            await ws.receive_text()  # keep-alive; client sends nothing important
    except WebSocketDisconnect:
        hub.clients.discard(ws)


FRONTEND = Path(__file__).resolve().parent.parent / "frontend"
if FRONTEND.exists():
    app.mount("/", StaticFiles(directory=FRONTEND, html=True), name="frontend")