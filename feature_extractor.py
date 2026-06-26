import os
import re
from pathlib import Path
from typing import Dict, Any

from PyPDF2 import PdfReader


def _safe_read_text(file_path: str) -> str:
    with open(file_path, "rb") as f:
        raw = f.read()
    return raw.decode("latin-1", errors="ignore")


def _count_regex(pattern: str, text: str) -> int:
    return len(re.findall(pattern, text, flags=re.IGNORECASE))


def _safe_len(value) -> int:
    try:
        return len(value)
    except Exception:
        return 0


def extract_features(file_path: str) -> Dict[str, Any]:
    path = Path(file_path)
    content = _safe_read_text(file_path)
    content_lower = content.lower()

    features = {
        "pdf_size": os.path.getsize(file_path),
        "metadata_size": len(content),
        "pages": 0,
        "xref_length": _count_regex(r"\bxref\b", content_lower),
        "title_characters": len(path.stem),
        "isEncrypted": 0,
        "embedded_files": 0,
        "images": 0,
        "contains_text": 0,
        "header": 0.0,
        "obj": _count_regex(r"\bobj\b", content_lower),
        "endobj": _count_regex(r"\bendobj\b", content_lower),
        "stream": _count_regex(r"\bstream\b", content_lower),
        "endstream": _count_regex(r"\bendstream\b", content_lower),
        "xref": _count_regex(r"\bxref\b", content_lower),
        "trailer": _count_regex(r"\btrailer\b", content_lower),
        "startxref": _count_regex(r"\bstartxref\b", content_lower),
        "pageno": _count_regex(r"/page\b", content_lower),
        "encrypt": _count_regex(r"/encrypt\b", content_lower),
        "ObjStm": _count_regex(r"/objstm\b", content_lower),
        "JS": _count_regex(r"/js\b", content_lower),
        "Javascript": _count_regex(r"/javascript\b", content_lower),
        "AA": _count_regex(r"/aa\b", content_lower),
        "OpenAction": _count_regex(r"/openaction\b", content_lower),
        "Acroform": _count_regex(r"/acroform\b", content_lower),
        "JBIG2Decode": _count_regex(r"/jbig2decode\b", content_lower),
        "RichMedia": _count_regex(r"/richmedia\b", content_lower),
        "launch": _count_regex(r"/launch\b", content_lower),
        "EmbeddedFile": _count_regex(r"/embeddedfile\b", content_lower),
        "XFA": _count_regex(r"/xfa\b", content_lower),
        "URI": _count_regex(r"/uri\b", content_lower),
        "Colors": _count_regex(r"/device(rgb|cmyk|gray)\b", content_lower),
    }

    header_match = re.search(r"%pdf-(\d+\.\d+)", content_lower)
    if header_match:
        try:
            features["header"] = float(header_match.group(1))
        except Exception:
            features["header"] = 0.0

    try:
        reader = PdfReader(file_path)
        features["pages"] = len(reader.pages)
        features["isEncrypted"] = int(bool(reader.is_encrypted))

        meta = reader.metadata or {}
        text_found = False
        image_count = 0
        embedded_guess = features["EmbeddedFile"]

        for page in reader.pages:
            try:
                txt = page.extract_text() or ""
                if txt.strip():
                    text_found = True
            except Exception:
                pass

            try:
                resources = page.get("/Resources", {})
                xobj = resources.get("/XObject", {}) if hasattr(resources, "get") else {}
                image_count += _safe_len(xobj)
            except Exception:
                pass

        features["contains_text"] = int(text_found)
        features["images"] = image_count
        features["embedded_files"] = embedded_guess
    except Exception:
        # keep default values if parsing fails
        pass

    return features
