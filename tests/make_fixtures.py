"""Generate OCR/PDF test fixtures: a dark-mode phone screenshot of a Microsoft 365
bounce, a PDF letter with a text layer, and the same letter as a scanned (image-only) PDF.

    python tests/make_fixtures.py <output-dir>
"""

from __future__ import annotations

import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

FONT = "C:/Windows/Fonts/arial.ttf"
BOLD = "C:/Windows/Fonts/arialbd.ttf"


def _font(size: int, bold: bool = False):
    try:
        return ImageFont.truetype(BOLD if bold else FONT, size)
    except OSError:
        return ImageFont.load_default(size)


def ndr_screenshot(path: Path) -> None:
    """Layout and wording follow a real Outlook/Gmail-on-Android bounce capture."""
    img = Image.new("RGB", (900, 2000), (24, 24, 24))
    d = ImageDraw.Draw(img)
    white, grey, blue, red = (235, 235, 235), (200, 200, 200), (138, 180, 248), (255, 120, 80)
    d.text((75, 50), "5:44", fill=white, font=_font(30, True))
    d.text((790, 50), "56", fill=white, font=_font(26, True))
    y = 375
    for text, colour, size in [
        ("Your message to the Microsoft 365 group group@agency.example.ca couldn't be", white, 24),
        ("delivered.", white, 24),
        ("The group GROUP isn't set up to receive messages", white, 34),
        ("from sender@example.com.", blue, 34),
    ]:
        d.text((50, y), text, fill=colour, font=_font(size))
        y += 32 if size == 24 else 46
    d.text((50, 590), "Sender", fill=white, font=_font(22))
    d.text((390, 590), "Office 365", fill=white, font=_font(22, True))
    d.text((680, 590), "Action Required", fill=red, font=_font(22, True))
    d.text((650, 660), "Sender not allowed", fill=red, font=_font(22))
    d.text((80, 740), "How to Fix It", fill=white, font=_font(30, True))
    y = 840
    for line in [
        "• If you're a member of the group, you might be registered with",
        "  an email address other than sender@example.com.",
        "• Ask the group owner to add sender@example.com as a",
        "  group member. If you don't know who the group owner is,",
        "  contact the organization's customer service department.",
        "• Ask the group owner to allow people outside their",
        "  organization to send email to the group.",
    ]:
        d.text((110, y), line, fill=white, font=_font(24))
        y += 30
    d.text((50, 1215), "More Info for Email Admins", fill=white, font=_font(30, True))
    d.text((50, 1255), "Status code: 550 5.7.193", fill=white, font=_font(21))
    y = 1305
    for line in [
        "The Microsoft 365 group, group@agency.example.ca, is configured to reject messages sent to",
        "it from outside its organization -- unless the sender is a guest group member.",
        "sender@example.com isn't part of the organization, and it isn't a guest group",
        "member.",
    ]:
        d.text((50, y), line, fill=grey, font=_font(19))
        y += 26
    d.text((50, 1555), "Original Message Details", fill=white, font=_font(26, True))
    rows = [
        ("Created Date:", "10/21/2026 9:38:40 PM"),
        ("Sender Address:", "sender@example.com"),
        ("Recipient Address:", "group@agency.example.ca"),
        ("Subject:", "RE: Request for Account Records and Review of the"),
        ("", "Restriction Notice Dated October 2, 2026"),
    ]
    y = 1590
    for label, value in rows:
        d.text((65, y), label, fill=white, font=_font(22, True))
        d.text((270, y), value, fill=blue if "@" in value else white, font=_font(22))
        y += 34
    img.save(path)


LETTER = [
    "Example Bank N.A.",
    "Risk Operations, PO Box 100, Toronto ON",
    "",
    "October 10, 2026",
    "",
    "Dear Customer,",
    "",
    "Your account ending 4421 has been restricted due to activity that does not meet our",
    "risk standards. This decision was made under Section 12.3 of the Deposit Account",
    "Agreement. Our systems flagged the account automatically.",
    "",
    "If you disagree, you may dispute this decision by writing to the address above",
    "within 30 days.",
    "",
    "Sincerely,",
    "Account Services",
]


def text_pdf(path: Path) -> None:
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas

    c = canvas.Canvas(str(path), pagesize=letter)
    y = 720
    for line in LETTER:
        c.drawString(72, y, line)
        y -= 16
    c.save()


def scanned_pdf(path: Path) -> None:
    """Image-only PDF, slightly rotated and grey, like a phone scan."""
    img = Image.new("RGB", (1700, 2200), (250, 248, 240))
    d = ImageDraw.Draw(img)
    y = 200
    for line in LETTER:
        d.text((150, y), line, fill=(40, 40, 40), font=_font(34))
        y += 52
    img = img.rotate(0.7, fillcolor=(250, 248, 240), expand=False)
    img.save(path, "PDF", resolution=200)


if __name__ == "__main__":
    out = Path(sys.argv[1] if len(sys.argv) > 1 else "tests/fixtures")
    out.mkdir(parents=True, exist_ok=True)
    ndr_screenshot(out / "ndr_screenshot.png")
    text_pdf(out / "letter_text.pdf")
    scanned_pdf(out / "letter_scanned.pdf")
    print(f"Fixtures written to {out}")
