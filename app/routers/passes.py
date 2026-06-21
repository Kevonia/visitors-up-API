"""Public (no-auth) pre-registration pass lookup.

A resident shares a link (e.g. via WhatsApp) containing a visitor's share_token;
the guest opens it to see their gate pass — no app/login needed. The QR the guard
scans is still the visitor id, so the existing gate scan flow is unchanged.
"""
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from .. import models, schemas
from ..utilities.db_util import get_db

router = APIRouter()

# Shareable web page for a pre-registered pass. The QR is rendered client-side
# (qrcodejs) from the visitor id, so the id never leaves the guest's browser.
_PASS_PAGE = """<!doctype html><html><head>
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Gate Pass</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js"></script>
<style>
body{font-family:system-ui,Segoe UI,Roboto,sans-serif;background:#1E5631;color:#fff;
display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0}
.card{background:#fff;color:#1A1F1B;border-radius:20px;padding:28px;max-width:340px;
width:88%;text-align:center;box-shadow:0 12px 40px rgba(0,0,0,.35)}
#qr{display:flex;justify-content:center;margin:18px 0}
.brand{color:#C9A227;font-weight:700;letter-spacing:2px;font-size:12px}
.n{font-size:23px;font-weight:800;margin-top:6px}.m{color:#6B7770}
.b{display:inline-block;background:#E8F5E9;color:#2E7D32;border-radius:999px;
padding:4px 12px;font-size:13px;font-weight:700;margin-top:10px}
</style></head><body><div class="card">
<div class="brand">TWICKENHAM GLADES</div>
<div class="n">__NAME__</div>
<div class="m">Lot __LOT__ · __REL__</div>
<div id="qr"></div>
<div class="b">__STATUS__</div>
<div class="m" style="margin-top:12px;font-size:12px">Show this pass at the gate.</div>
</div>
<script>new QRCode(document.getElementById("qr"),{text:"__VID__",width:200,height:200});</script>
</body></html>"""


@router.get("/passes/{share_token}", response_model=schemas.PublicPass)
def public_pass(share_token: str, db: Session = Depends(get_db)):
    v = (
        db.query(models.Visitor)
        .filter(models.Visitor.share_token == share_token)
        .first()
    )
    if not v:
        raise HTTPException(status_code=404, detail="Pass not found")
    return {
        "id": str(v.id),
        "name": v.name,
        "relationship_type": v.relationship_type,
        "visit_type": v.visit_type.value if v.visit_type else None,
        "status": v.effective_status().value,
        "lot_no": v.created_by_user.lot_no if v.created_by_user else None,
        "resident_name": v.created_by_user.name if v.created_by_user else None,
        "valid_from": v.valid_from,
        "valid_until": v.valid_until,
    }


@router.get("/passes/{share_token}/view", response_class=HTMLResponse)
def public_pass_view(share_token: str, db: Session = Depends(get_db)):
    """A shareable web page (QR + details) a resident can WhatsApp to a guest."""
    v = (
        db.query(models.Visitor)
        .filter(models.Visitor.share_token == share_token)
        .first()
    )
    if not v:
        return HTMLResponse("<h1 style='font-family:system-ui'>Pass not found</h1>",
                            status_code=404)
    lot = v.created_by_user.lot_no if v.created_by_user else "—"
    html = (
        _PASS_PAGE
        .replace("__NAME__", v.name or "Visitor")
        .replace("__LOT__", lot or "—")
        .replace("__REL__", v.relationship_type or "guest")
        .replace("__STATUS__", v.effective_status().value)
        .replace("__VID__", str(v.id))
    )
    return HTMLResponse(html)
