"""FastAPI entrypoint."""
from __future__ import annotations

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from app.backend.auth import verify_admin
from app.backend.pipeline import handle_request
from app.controls import controls

app = FastAPI(title="AI IT Incident Response Agent (mock mode)")


class IncidentIn(BaseModel):
    user_id: str = Field(min_length=1, max_length=64)
    message: str = Field(min_length=1, max_length=4000)
    session_id: str = Field(default="", max_length=128)


class KillSwitchIn(BaseModel):
    enabled: bool


@app.post("/incident")
async def post_incident(body: IncidentIn, authorization: str | None = Header(default=None)) -> JSONResponse:
    result = await handle_request(body.user_id, body.message, body.session_id or body.user_id,
                                  authorization=authorization)
    return JSONResponse(result, status_code=result["status"])


@app.post("/admin/kill-switch")
async def post_kill_switch(body: KillSwitchIn, authorization: str | None = Header(default=None)) -> dict:
    if not verify_admin(authorization):
        raise HTTPException(status_code=401, detail="admin token required")
    controls.kill_switch = body.enabled
    return {"kill_switch": controls.kill_switch}
