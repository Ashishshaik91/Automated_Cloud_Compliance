"""
Terraform State Ingestion API routes.

Provides two real-time fetch paths:
  POST /api/v1/terraform/ingest
      Upload a .tfstate JSON file → parse and return normalised resource list.
      No Terraform binary required.

  POST /api/v1/terraform/show-json
      Run `terraform show -json` in a server-side project directory.
      Requires:  TERRAFORM_MODE=binary  AND  Terraform CLI installed in container.
      The working_dir must be an absolute path to a directory that exists on the server.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Annotated, Any

import structlog
from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import CurrentUser
from app.auth.scoping import require_write_access, get_org_scope
from app.connectors.terraform_connector import TerraformConnector, _parse_tfstate
from app.models.database import get_db

router = APIRouter()
logger = structlog.get_logger(__name__)

_MAX_STATE_FILE_BYTES = 10 * 1024 * 1024  # 10 MB


# ── Request / Response schemas ──────────────────────────────────────────────

class TerraformIngestResponse(BaseModel):
    resource_count: int
    resources: list[dict[str, Any]]
    source: str  # "upload" | "binary"


class TerraformShowJsonRequest(BaseModel):
    working_dir: str = Field(
        ...,
        description=(
            "Absolute path to the Terraform project directory on the server. "
            "`terraform show -json` will be executed there."
        ),
    )
    account_id: str = Field(
        default="",
        description="Optional cloud account ID for Redis advisory lock key.",
    )


# ── Endpoints ───────────────────────────────────────────────────────────────

@router.post(
    "/ingest",
    response_model=TerraformIngestResponse,
    status_code=status.HTTP_200_OK,
    summary="Upload a .tfstate file and parse its resources",
)
async def ingest_tfstate_file(
    current_user: CurrentUser,
    db: Annotated[AsyncSession, Depends(get_db)],
    file: UploadFile = File(..., description="A Terraform .tfstate JSON file"),
) -> TerraformIngestResponse:
    """
    Upload a `.tfstate` file and receive a normalised list of its managed resources.

    This is the *no-binary* path — no Terraform CLI is needed. The file is parsed
    entirely in Python. Useful when you export state with:
        terraform state pull > terraform.tfstate
    and then POST the file here.
    """
    scope = await get_org_scope(current_user, db)
    require_write_access(scope)  # Auditors cannot ingest state

    if file.content_type not in ("application/json", "application/octet-stream", None):
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail="Only JSON .tfstate files are accepted.",
        )

    raw_bytes = await file.read(_MAX_STATE_FILE_BYTES + 1)
    if len(raw_bytes) > _MAX_STATE_FILE_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="State file exceeds 10 MB limit.",
        )

    try:
        raw = json.loads(raw_bytes)
    except json.JSONDecodeError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"File is not valid JSON: {exc}",
        )

    resources = _parse_tfstate(raw)
    logger.info(
        "Terraform state file ingested via upload",
        filename=file.filename,
        resource_count=len(resources),
        user_id=current_user.id,
    )
    return TerraformIngestResponse(
        resource_count=len(resources),
        resources=resources,
        source="upload",
    )


@router.post(
    "/show-json",
    response_model=TerraformIngestResponse,
    status_code=status.HTTP_200_OK,
    summary="Run terraform show -json in a server-side directory",
)
async def run_terraform_show_json(
    body: TerraformShowJsonRequest,
    current_user: CurrentUser,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> TerraformIngestResponse:
    """
    Execute `terraform show -json` inside a server-side Terraform project directory
    and return the parsed resource list.

    **Requirements:**
    - `TERRAFORM_MODE=binary` must be set in the server environment.
    - Terraform CLI must be installed and on the server's `PATH`.
    - The `working_dir` must be an absolute path that exists on the server and
      contains an initialised Terraform state (`.terraform/` + state file).

    This is the *real-time fetch* path that pipes `terraform show -json`
    directly into the compliance scanner.
    """
    scope = await get_org_scope(current_user, db)
    require_write_access(scope)

    working_dir = Path(body.working_dir)

    # Security: reject path traversal attempts and non-absolute paths
    if not working_dir.is_absolute():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="working_dir must be an absolute path.",
        )
    if not working_dir.exists() or not working_dir.is_dir():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Directory not found: {working_dir}",
        )

    tf = TerraformConnector.from_working_dir(
        working_dir=working_dir,
        account_id=body.account_id,
    )

    try:
        resources = await tf.enumerate_resources()
    except Exception as exc:
        logger.error(
            "terraform show -json failed via API",
            working_dir=str(working_dir),
            error=str(exc),
        )
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"terraform show -json failed: {exc}",
        )

    logger.info(
        "terraform show -json completed via API",
        working_dir=str(working_dir),
        resource_count=len(resources),
        user_id=current_user.id,
    )
    return TerraformIngestResponse(
        resource_count=len(resources),
        resources=resources,
        source="binary",
    )
