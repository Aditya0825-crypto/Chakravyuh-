"""PoV Verifier REST endpoints."""

from pathlib import Path

from fastapi import APIRouter, HTTPException

from api.schemas.pov import PoVVerifyRequest, PoVVerifyResponse, VerifiedPoVOut
from core.pov.models import PoVVerifyOptions
from core.pov.verify import verify_pov, verify_pov_from_stderr

router = APIRouter(prefix="/pov", tags=["pov"])


@router.post("/verify", response_model=PoVVerifyResponse)
def verify_pov_endpoint(body: PoVVerifyRequest):
    binary = Path(body.binary_path)
    if not binary.is_file():
        raise HTTPException(status_code=400, detail=f"Binary not found: {binary}")

    pov = verify_pov(
        body.crashing_input,
        binary,
        options=PoVVerifyOptions(
            static_finding_match=body.static_finding_match,
            work_dir=str(binary.parent),
        ),
    )
    if not pov:
        return PoVVerifyResponse(
            verified=False,
            message="No sanitizer crash reproduced — return code or evidence insufficient",
        )
    return PoVVerifyResponse(
        verified=True,
        pov=VerifiedPoVOut(**pov.to_api_dict()),
    )


@router.post("/verify-stderr", response_model=PoVVerifyResponse)
def verify_from_stderr(
    stderr: str,
    return_code: int = 134,
    crashing_input: str = "",
):
    """Offline triage — classify pre-captured ASan stderr."""
    pov = verify_pov_from_stderr(
        stderr,
        return_code=return_code,
        crashing_input=crashing_input,
    )
    if not pov:
        return PoVVerifyResponse(verified=False, message="Could not verify from stderr")
    return PoVVerifyResponse(verified=True, pov=VerifiedPoVOut(**pov.to_api_dict()))
