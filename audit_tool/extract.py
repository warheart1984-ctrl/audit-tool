"""Get text out of screenshots and PDFs.

PDFs: the embedded text layer is read first (pypdf). Pages with no usable text,
such as scanned letters, are rendered (pypdfium2) and run through OCR.
Images: OCR with RapidOCR (pip-installable, no system binary) or, if that isn't
installed, Tesseract via pytesseract.

All of these are optional. Without them, files are still preserved and hashed,
and their facts are entered by hand with `audit edit`.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass, field
from pathlib import Path
from statistics import mean, median

# A page with fewer readable characters than this is treated as scanned.
MIN_PAGE_CHARS = 40
PDF_RENDER_DPI = 300


@dataclass
class ExtractedText:
    text: str = ""
    method: str = ""  # e.g. "pdf-text", "ocr:rapidocr", "pdf-text+ocr:rapidocr"
    confidence: float | None = None  # mean OCR confidence, 0..1
    warnings: list[str] = field(default_factory=list)

    def summary(self) -> str:
        conf = f", mean OCR confidence {self.confidence:.2f}" if self.confidence is not None else ""
        return f"Text extracted by {self.method}{conf}. Check it against the original."


_rapid_engine = None


def _rapidocr():
    global _rapid_engine
    if _rapid_engine is None:
        from rapidocr_onnxruntime import RapidOCR  # optional dependency
        _rapid_engine = RapidOCR()
    return _rapid_engine


def _prepare(img):
    """RGB, upscaled if tiny, and inverted if it's a dark-mode capture."""
    from PIL import Image, ImageOps, ImageStat

    img = img.convert("RGB")
    # Upscaling phone-sized captures makes RapidOCR merge words, so only fix tiny images.
    if img.width < 600:
        factor = 900 / img.width
        img = img.resize((round(img.width * factor), round(img.height * factor)), Image.LANCZOS)
    if ImageStat.Stat(img.convert("L")).mean[0] < 100:
        img = ImageOps.invert(img)
    return img


def _group_lines(boxes: list[tuple[float, float, float, str]]) -> str:
    """Rebuild reading order from (top, left, height, text) boxes."""
    if not boxes:
        return ""
    tolerance = median(b[2] for b in boxes) * 0.6
    lines: list[list[tuple[float, float, float, str]]] = []
    for box in sorted(boxes):
        if lines and abs(box[0] - lines[-1][0][0]) <= tolerance:
            lines[-1].append(box)
        else:
            lines.append([box])
    return "\n".join(" ".join(b[3] for b in sorted(line, key=lambda b: b[1])) for line in lines)


def ocr_image(img) -> tuple[str, str, float | None]:
    """OCR a PIL image. Returns (text, engine, mean confidence)."""
    img = _prepare(img)
    try:
        result, _ = _rapidocr()(img)
        boxes, scores = [], []
        for points, text, score in result or []:
            ys = [p[1] for p in points]
            boxes.append((min(ys), min(p[0] for p in points), max(ys) - min(ys), text))
            scores.append(float(score))
        return _group_lines(boxes), "rapidocr", (mean(scores) if scores else None)
    except ImportError:
        pass
    try:
        import pytesseract
    except ImportError:
        raise RuntimeError("No OCR engine installed. Run: pip install rapidocr_onnxruntime") from None
    if not shutil.which("tesseract"):
        raise RuntimeError("pytesseract is installed but the tesseract program is not on PATH")
    return pytesseract.image_to_string(img), "tesseract", None


def extract_image(path: Path) -> ExtractedText:
    from PIL import Image

    with Image.open(path) as img:
        img.load()
        text, engine, conf = ocr_image(img)
    return ExtractedText(text=text, method=f"ocr:{engine}", confidence=conf)


def extract_pdf(path: Path) -> ExtractedText:
    from pypdf import PdfReader

    reader = PdfReader(str(path))
    if reader.is_encrypted and not reader.decrypt(""):
        return ExtractedText(warnings=["PDF is password-protected; text was not extracted"])

    out = ExtractedText()
    methods, confs, pages = set(), [], []
    for i, page in enumerate(reader.pages):
        text = page.extract_text() or ""
        if len("".join(text.split())) >= MIN_PAGE_CHARS:
            methods.add("pdf-text")
            pages.append(text)
            continue
        try:
            import pypdfium2 as pdfium

            pdf = pdfium.PdfDocument(str(path))
            img = pdf[i].render(scale=PDF_RENDER_DPI / 72).to_pil()
            ocr_text, engine, conf = ocr_image(img)
            methods.add(f"ocr:{engine}")
            if conf is not None:
                confs.append(conf)
            pages.append(ocr_text)
        except ImportError:
            out.warnings.append(f"page {i + 1} has no text layer; install pypdfium2 to OCR it")
            pages.append(text)
        except RuntimeError as exc:
            out.warnings.append(f"page {i + 1}: {exc}")
            pages.append(text)
    out.text = "\n\n".join(pages)
    out.method = "+".join(sorted(methods)) or "none"
    out.confidence = mean(confs) if confs else None
    return out


def extract(path: Path) -> ExtractedText:
    try:
        if path.suffix.lower() == ".pdf":
            return extract_pdf(path)
        return extract_image(path)
    except ImportError as exc:
        return ExtractedText(warnings=[f"text extraction unavailable: {exc}"])
    except RuntimeError as exc:
        return ExtractedText(warnings=[str(exc)])
    except Exception as exc:  # corrupt or unsupported file: keep the evidence, skip the text
        return ExtractedText(warnings=[f"could not read file for text extraction: {exc}"])
