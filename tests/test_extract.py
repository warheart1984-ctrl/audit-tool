"""Bounded extraction from screenshots and PDFs (F5)."""

from __future__ import annotations

import pytest

from audit_tool import extract as ex


def test_oversized_image_is_refused_before_decoding(tmp_path, monkeypatch):
    Image = pytest.importorskip("PIL.Image")
    monkeypatch.setattr(ex, "MAX_IMAGE_PIXELS", 100)
    f = tmp_path / "big.png"
    Image.new("RGB", (20, 20)).save(f)
    result = ex.extract(f)
    assert result.text == ""
    assert any("pixel OCR limit" in w for w in result.warnings)


def test_pdf_page_cap(tmp_path, monkeypatch):
    pytest.importorskip("pypdf")
    canvas = pytest.importorskip("reportlab.pdfgen.canvas")
    f = tmp_path / "long.pdf"
    c = canvas.Canvas(str(f))
    for n in range(3):
        c.drawString(72, 720, f"Page {n + 1}: your account has been restricted under section 12.")
        c.showPage()
    c.save()
    monkeypatch.setattr(ex, "MAX_PDF_PAGES", 2)
    result = ex.extract(f)
    assert "Page 2" in result.text and "Page 3" not in result.text
    assert any("only the first 2" in w for w in result.warnings)


def test_corrupt_file_becomes_a_warning(tmp_path):
    f = tmp_path / "broken.png"
    f.write_bytes(b"\x89PNG\r\n\x1a\nnot really")
    result = ex.extract(f)
    assert result.text == "" and result.warnings
