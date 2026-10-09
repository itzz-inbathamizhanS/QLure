"""PDF report for a standard domain scan, built from the scan result the page already shows."""

from __future__ import annotations

from typing import Any

from fpdf import FPDF
from fpdf.enums import MethodReturnValue

SEVERITIES = ("high", "medium", "low", "info")
MAX_FINDINGS = 200
MAX_SUBDOMAINS = 60
MAX_FIELD = 1500
HIDDEN_CHECKS = {"requires_verification"}  # active checks that only a full scan runs

NAVY = (16, 33, 62)
INK = (31, 41, 55)
MUTED = (107, 114, 128)
LINE = (219, 223, 230)
ZEBRA = (245, 247, 250)
WHITE = (255, 255, 255)
GOOD = (21, 128, 61)
GOOD_TINT = (236, 247, 240)
WARN_TINT = (254, 247, 232)
SEVERITY = {  # colour, tint, label
    "high": ((192, 38, 38), (253, 240, 240), "HIGH"),
    "medium": ((202, 118, 4), (254, 246, 230), "MEDIUM"),
    "low": ((37, 99, 235), (238, 243, 254), "LOW"),
    "info": ((71, 85, 105), (244, 246, 249), "INFO"),
}

X0 = 15.0
WIDTH = 180.0
_PUNCTUATION = str.maketrans(
    {
        "–": "-",
        "—": "-",
        "‘": "'",
        "’": "'",
        "“": '"',
        "”": '"',
        "…": "...",
        "→": "->",
        "·": "|",
        "•": "-",
    }
)


def _text(value: Any) -> str:
    """Text safe for the built-in PDF fonts: Latin-1 only, no control characters, bounded."""
    s = "" if value is None else str(value)[:MAX_FIELD]
    s = s.translate(_PUNCTUATION)
    s = "".join(ch if ch >= " " or ch == "\n" else " " for ch in s)
    s = s.encode("latin-1", "replace").decode("latin-1")
    return s.replace("**", "* *").replace("__", "_ _").replace("--", "- -")  # no inline markup


def _get(obj: Any, *path: str) -> Any:
    for key in path:
        obj = obj.get(key) if isinstance(obj, dict) else None
    return obj


def _list(value: Any) -> list:
    return value if isinstance(value, list) else []


class _Report(FPDF):
    target = ""

    def footer(self) -> None:
        self.set_y(-13)
        self.set_draw_color(*LINE)
        self.line(X0, self.get_y(), X0 + WIDTH, self.get_y())
        self.set_font("Helvetica", "", 8)
        self.set_text_color(*MUTED)
        self.set_y(-11)
        self.cell(WIDTH / 2, 5, _text(f"Q-Lure domain scan report  |  {self.target}"))
        self.cell(WIDTH / 2, 5, f"Page {self.page_no()} of {{nb}}", align="R")


def _height(
    pdf: _Report,
    width: float,
    text: str,
    line: float,
    size: float,
    style: str = "",
    markdown: bool = False,
) -> float:
    pdf.set_font("Helvetica", style, size)
    return pdf.multi_cell(
        width,
        line,
        text,
        align="L",
        markdown=markdown,
        dry_run=True,
        output=MethodReturnValue.HEIGHT,
    )


def _room(pdf: _Report, needed: float) -> None:
    if pdf.get_y() + needed > pdf.page_break_trigger:
        pdf.add_page()


def _section(pdf: _Report, title: str) -> None:
    _room(pdf, 22)
    pdf.ln(5)
    y = pdf.get_y()
    pdf.set_fill_color(*NAVY)
    pdf.rect(X0, y + 0.8, 1.8, 5.2, style="F")
    pdf.set_xy(X0 + 4.5, y)
    pdf.set_font("Helvetica", "B", 12.5)
    pdf.set_text_color(*NAVY)
    pdf.cell(0, 7, _text(title), new_x="LMARGIN", new_y="NEXT")
    pdf.set_draw_color(*LINE)
    pdf.line(X0, pdf.get_y() + 0.5, X0 + WIDTH, pdf.get_y() + 0.5)
    pdf.ln(3.5)


def _header(pdf: _Report, result: dict[str, Any]) -> None:
    pdf.set_fill_color(*NAVY)
    pdf.rect(0, 0, 210, 44, style="F")
    pdf.set_fill_color(56, 189, 248)
    pdf.rect(0, 44, 210, 1.4, style="F")
    pdf.set_xy(X0, 11)
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_text_color(147, 197, 253)
    pdf.cell(0, 5, "Q-LURE  |  POST-QUANTUM READINESS", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "B", 22)
    pdf.set_text_color(*WHITE)
    pdf.cell(0, 11, "Domain scan report", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 11)
    pdf.set_text_color(226, 232, 240)
    stamp = str(result.get("scan_timestamp") or "")[:19].replace("T", " ")
    pdf.cell(
        0,
        6,
        _text(f"{result.get('target_url', '')}   |   Standard scan   |   {stamp} UTC"),
        new_x="LMARGIN",
        new_y="NEXT",
    )
    pdf.set_y(52)


def _posture(pdf: _Report, result: dict[str, Any]) -> None:
    summary = _get(result, "pqc_posture", "summary")
    if not summary:
        return
    hybrid = _get(result, "pqc_posture", "key_exchange") == "hybrid_pqc"
    colour, tint = (GOOD, GOOD_TINT) if hybrid else (SEVERITY["medium"][0], WARN_TINT)
    title = "Quantum-safe key exchange in use" if hybrid else "Key exchange is not post-quantum"
    body = _text(summary)
    h = 12 + _height(pdf, WIDTH - 10, body, 4.8, 9.5)
    _room(pdf, h + 2)
    y = pdf.get_y()
    pdf.set_fill_color(*tint)
    pdf.rect(X0, y, WIDTH, h, style="F")
    pdf.set_fill_color(*colour)
    pdf.rect(X0, y, 2, h, style="F")
    pdf.set_xy(X0 + 6, y + 3)
    pdf.set_font("Helvetica", "B", 10.5)
    pdf.set_text_color(*colour)
    pdf.cell(0, 5, title, new_x="LEFT", new_y="NEXT")
    pdf.set_x(X0 + 6)
    pdf.set_font("Helvetica", "", 9.5)
    pdf.set_text_color(*INK)
    pdf.multi_cell(WIDTH - 10, 4.8, body, align="L", new_x="LMARGIN", new_y="NEXT")
    pdf.set_y(y + h + 2)


def _counts(pdf: _Report, counts: dict[str, int]) -> None:
    gap, w, h = 4.0, (WIDTH - 12.0) / 4, 21.0
    _room(pdf, h + 2)
    y = pdf.get_y()
    for i, sev in enumerate(SEVERITIES):
        colour, tint, label = SEVERITY[sev]
        x = X0 + i * (w + gap)
        pdf.set_fill_color(*tint)
        pdf.rect(x, y, w, h, style="F")
        pdf.set_fill_color(*colour)
        pdf.rect(x, y, w, 1.6, style="F")
        pdf.set_xy(x, y + 3.5)
        pdf.set_font("Helvetica", "B", 20)
        pdf.set_text_color(*colour)
        pdf.cell(w, 9, str(counts[sev]), align="C")
        pdf.set_xy(x, y + 13.5)
        pdf.set_font("Helvetica", "B", 7.5)
        pdf.set_text_color(*MUTED)
        pdf.cell(w, 4, label, align="C")
    pdf.set_y(y + h + 2)


def _table(pdf: _Report, rows: list[tuple[str, Any]], label_w: float = 40.0) -> None:
    """Label / value rows with zebra shading. A missing value reads 'not observed'."""
    for i, (label, value) in enumerate(rows):
        text = _text(value if value not in (None, "") else "not observed")
        h = max(6.2, _height(pdf, WIDTH - label_w - 4, text, 4.8, 9) + 1.6)
        _room(pdf, h)
        y = pdf.get_y()
        if i % 2 == 0:
            pdf.set_fill_color(*ZEBRA)
            pdf.rect(X0, y, WIDTH, h, style="F")
        pdf.set_xy(X0 + 3, y + 0.9)
        pdf.set_font("Helvetica", "B", 8.5)
        pdf.set_text_color(*MUTED)
        pdf.cell(label_w - 3, 4.8, _text(label).upper())
        pdf.set_xy(X0 + label_w, y + 0.9)
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(*INK)
        pdf.multi_cell(WIDTH - label_w - 3, 4.8, text, align="L", new_x="LMARGIN", new_y="NEXT")
        pdf.set_y(y + h)


def _checks(pdf: _Report, checks: dict[str, Any]) -> None:
    rows = []
    for name, c in checks.items():
        c = c if isinstance(c, dict) else {}
        status = str(c.get("status") or "")
        if status not in HIDDEN_CHECKS:
            rows.append((str(name), status, c.get("reason")))
    if not rows:
        return
    _section(pdf, "Checks run")
    has_detail = any(r[2] for r in rows)
    col = (48.0, 24.0, WIDTH - 72.0) if has_detail else (WIDTH / 2, WIDTH / 2, 0.0)
    pdf.set_fill_color(*NAVY)
    pdf.rect(X0, pdf.get_y(), WIDTH, 6.5, style="F")
    pdf.set_font("Helvetica", "B", 8)
    pdf.set_text_color(*WHITE)
    pdf.set_x(X0 + 3)
    for head, w in zip(("CHECK", "STATUS", "DETAIL"), col, strict=True):
        if w:
            pdf.cell(w, 6.5, head)
    pdf.ln(6.5)
    for i, (name, status, reason) in enumerate(rows):
        detail = _text(reason or "")
        h = max(
            5.8, (_height(pdf, col[2] - 3, detail, 4.4, 8.5) + 2.2) if has_detail and detail else 0
        )
        _room(pdf, h)
        y = pdf.get_y()
        if i % 2 == 1:
            pdf.set_fill_color(*ZEBRA)
            pdf.rect(X0, y, WIDTH, h, style="F")
        ok = status == "ok"
        colour = GOOD if ok else (SEVERITY["high"][0] if status == "failed" else MUTED)
        pdf.set_xy(X0 + 3, y + 1.1)
        pdf.set_font("Helvetica", "", 8.5)
        pdf.set_text_color(*INK)
        pdf.cell(col[0], 4.4, _text(name))
        pdf.set_font("Helvetica", "B", 8.5)
        pdf.set_text_color(*colour)
        pdf.cell(col[1], 4.4, _text(status.replace("_", " ").upper() or "-"))
        if has_detail and detail:
            pdf.set_font("Helvetica", "", 8.5)
            pdf.set_text_color(*MUTED)
            pdf.set_xy(X0 + 3 + col[0] + col[1], y + 1.1)
            pdf.multi_cell(col[2] - 3, 4.4, detail, align="L", new_x="LMARGIN", new_y="NEXT")
        pdf.set_y(y + h)
    pdf.set_draw_color(*LINE)
    pdf.line(X0, pdf.get_y(), X0 + WIDTH, pdf.get_y())


def _finding(pdf: _Report, f: dict[str, Any]) -> None:
    sev = f.get("severity") if f.get("severity") in SEVERITY else "info"
    colour, tint, label = SEVERITY[sev]
    inner = WIDTH - 9.0
    title = _text(f.get("title"))
    badge_w = 4.0 + pdf.get_string_width(label) * 1.12
    pdf.set_font("Helvetica", "B", 10)
    parts = [(title, 10.0, "B", 5.0, INK, 0.0, False)]
    if f.get("detail"):
        parts.append((_text(f["detail"]), 9.0, "", 4.6, INK, 1.2, False))
    if f.get("evidence"):
        parts.append((f"**Evidence:** {_text(f['evidence'])}", 8.5, "", 4.3, MUTED, 1.2, True))
    if f.get("recommendation"):
        parts.append((f"**Fix:** {_text(f['recommendation'])}", 8.8, "", 4.5, colour, 1.2, True))
    heights = [
        _height(pdf, inner - badge_w - 3 if i == 0 else inner, txt, lh, size, style, markdown=md)
        for i, (txt, size, style, lh, _c, _g, md) in enumerate(parts)
    ]
    total = 5.5 + sum(heights) + sum(p[5] for p in parts) + 2.5
    _room(pdf, total + 3)
    y = pdf.get_y()
    pdf.set_fill_color(*tint)
    pdf.rect(X0, y, WIDTH, total, style="F")
    pdf.set_fill_color(*colour)
    pdf.rect(X0, y, 2.2, total, style="F")
    pdf.set_fill_color(*colour)
    pdf.rect(X0 + 6.5, y + 3.2, badge_w, 5.0, style="F", round_corners=True, corner_radius=1.0)
    pdf.set_xy(X0 + 6.5, y + 3.2)
    pdf.set_font("Helvetica", "B", 7.5)
    pdf.set_text_color(*WHITE)
    pdf.cell(badge_w, 5.0, label, align="C")
    cy = y + 3.0
    for i, ((txt, size, style, lh, ink, gap, md), h) in enumerate(zip(parts, heights, strict=True)):
        cy += gap
        left = X0 + 6.5 + (badge_w + 3 if i == 0 else 0)
        pdf.set_xy(left, cy)
        pdf.set_font("Helvetica", style, size)
        pdf.set_text_color(*ink)
        pdf.multi_cell(
            inner - (badge_w + 3 if i == 0 else 0),
            lh,
            txt,
            align="L",
            markdown=md,
            new_x="LMARGIN",
            new_y="NEXT",
        )
        cy += h
        if i == 0:
            cy += 1.0
    pdf.set_y(y + total + 2.5)


def scan_pdf(result: dict[str, Any]) -> bytes:
    """Render a scan result (from dashboard.scanning.run) as a PDF. Tolerates missing parts."""
    tls = _get(result, "tls") or {}
    cert = _get(tls, "certificate") or {}
    kex = _get(tls, "key_exchange") or {}
    findings = [f for f in _list(result.get("findings")) if isinstance(f, dict)][:MAX_FINDINGS]
    order = {s: i for i, s in enumerate(SEVERITIES)}
    findings.sort(key=lambda f: order.get(f.get("severity"), len(order)))
    counts = {s: sum(1 for f in findings if f.get("severity") == s) for s in SEVERITIES}

    pdf = _Report(format="A4")
    pdf.target = str(result.get("target_url") or "")
    pdf.alias_nb_pages()
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.set_margins(X0, 15, X0)
    pdf.set_title(_text(f"Q-Lure scan report: {pdf.target}"))
    pdf.set_creator("Q-Lure")
    pdf.add_page()
    _header(pdf, result)

    _section(pdf, "Summary")
    _posture(pdf, result)
    _counts(pdf, counts)

    _section(pdf, "TLS and certificate")
    days = cert.get("days_remaining")
    expires = str(cert.get("not_after") or "")[:10]
    key = " ".join(str(p) for p in (cert.get("public_key_algorithm"), cert.get("key_size")) if p)
    _table(
        pdf,
        [
            ("TLS version", tls.get("version")),
            ("Cipher suite", tls.get("cipher_suite")),
            ("Key exchange", kex.get("preferred_group_name") or kex.get("kex")),
            (
                "Trusted",
                "Yes"
                if tls.get("trusted")
                else (f"No: {tls['trust_error']}" if tls.get("trust_error") else None),
            ),
            ("Certificate", cert.get("subject_cn")),
            ("Issuer", cert.get("issuer_cn")),
            ("Public key", key or None),
            (
                "Expires",
                f"{expires} ({days} days left)"
                if expires and days is not None
                else expires or None,
            ),
            ("Addresses", ", ".join(str(a) for a in _list(result.get("resolved_addresses")))),
        ],
    )
    for line in _list(kex.get("evidence")):
        _room(pdf, 6)
        pdf.set_x(X0 + 3)
        pdf.set_font("Helvetica", "", 8)
        pdf.set_text_color(*MUTED)
        pdf.multi_cell(WIDTH - 6, 4.2, _text(f"- {line}"), align="L", new_x="LMARGIN", new_y="NEXT")

    checks = result.get("checks")
    if isinstance(checks, dict) and checks:
        _checks(pdf, checks)

    _section(pdf, f"Findings ({len(findings)})")
    if not findings:
        pdf.set_font("Helvetica", "", 9.5)
        pdf.set_text_color(*MUTED)
        pdf.multi_cell(
            0,
            5,
            "No findings. Every check that ran passed, or was not applicable.",
            new_x="LMARGIN",
            new_y="NEXT",
        )
    for f in findings:
        _finding(pdf, f)

    names = [s.get("name") for s in _list(result.get("subdomains")) if isinstance(s, dict)]
    names = [str(n) for n in names if n]
    if names:
        _section(pdf, f"Subdomains ({len(names)})")
        shown = names[:MAX_SUBDOMAINS]
        extra = len(names) - len(shown)
        pdf.set_font("Courier", "", 8.5)
        pdf.set_text_color(*INK)
        pdf.multi_cell(
            0,
            4.8,
            _text("   ".join(shown) + (f"   (+{extra} more)" if extra > 0 else "")),
            align="L",
            new_x="LMARGIN",
            new_y="NEXT",
        )

    pdf.ln(5)
    pdf.set_font("Helvetica", "I", 8)
    pdf.set_text_color(*MUTED)
    pdf.multi_cell(
        0,
        4.2,
        "Generated by Q-Lure from public information (DNS, WHOIS, HTTP headers, "
        "TLS handshake, certificate transparency). Nothing about this scan is stored.",
        align="L",
        new_x="LMARGIN",
        new_y="NEXT",
    )
    return bytes(pdf.output())
