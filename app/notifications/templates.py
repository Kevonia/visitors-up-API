"""Branded HTML email templates (Twickenham Glades).

Email-client-safe: table-based layout with inline styles, a solid-colour
fallback under the gradient header, and an absolute logo URL (emails can't load
local assets). Keep it simple — many clients strip <style> and modern CSS.
"""
from app.config.config import settings

# Brand palette (kept in sync with the apps' TgBrand).
_FOREST = "#1E5631"
_LEAF = "#3E8E5A"
_GOLD = "#C9A227"
_SAND = "#F5F3EC"
_INK = "#1A1F1B"
_MIST = "#6B7770"
_BORDER = "#E7E3D8"

# Per-category badge colours for announcements.
CATEGORY_COLORS = {
    "info": _LEAF,
    "event": "#2F6DB5",
    "maintenance": "#E08A1E",
    "urgent": "#C0392B",
    "visitor": _LEAF,
}


def _logo_url() -> str:
    return f"{settings.public_base_url.rstrip('/')}/static/logo.png"


def render_email(heading: str, body_html: str, badge: str = None, badge_color: str = None) -> str:
    """Wrap content in the branded Twickenham Glades email shell."""
    color = badge_color or _GOLD
    badge_html = ""
    if badge:
        badge_html = (
            f'<div style="display:inline-block;background:{color}1f;color:{color};'
            f'font-size:12px;font-weight:700;padding:5px 12px;border-radius:999px;'
            f'margin-bottom:14px;text-transform:uppercase;letter-spacing:.6px;">{badge}</div>'
        )

    return f"""\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
</head>
<body style="margin:0;padding:0;background:{_SAND};font-family:'Segoe UI',Helvetica,Arial,sans-serif;color:{_INK};">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:{_SAND};padding:24px 12px;">
    <tr>
      <td align="center">
        <table role="presentation" width="600" cellpadding="0" cellspacing="0"
               style="max-width:600px;width:100%;background:#ffffff;border-radius:16px;overflow:hidden;border:1px solid {_BORDER};">
          <tr>
            <td align="center"
                style="background:{_FOREST};background:linear-gradient(135deg,{_FOREST},{_LEAF});padding:30px 32px;">
              <img src="{_logo_url()}" width="60" height="60" alt="Twickenham Glades"
                   style="display:block;border-radius:14px;background:#ffffff;padding:6px;margin:0 auto 12px;">
              <div style="color:#ffffff;font-size:20px;font-weight:700;letter-spacing:.3px;">Twickenham Glades</div>
            </td>
          </tr>
          <tr>
            <td style="padding:32px;">
              {badge_html}
              <h1 style="margin:0 0 14px;font-size:22px;font-weight:800;color:{_FOREST};line-height:1.25;">{heading}</h1>
              <div style="font-size:15px;line-height:1.65;color:{_INK};">{body_html}</div>
            </td>
          </tr>
          <tr>
            <td align="center" style="padding:20px 32px;background:{_SAND};border-top:1px solid {_BORDER};">
              <div style="font-size:12px;color:{_MIST};">Twickenham Glades &middot; Automated notification</div>
              <div style="font-size:12px;color:{_MIST};margin-top:4px;">Please do not reply to this email.</div>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>"""
