#!/usr/bin/env python3
"""
Generate test PDFs for the reference PDF→Fountain extractor using PyMuPDF.

Produces FD-convention screenplay PDFs in spec/v1/testvectors/pdf-extraction/
with each line at the canonical column positions a working extractor must
classify correctly. PyMuPDF emits PDFs that pdf2json parses cleanly (reportlab
produces XRef structures pdf2json chokes on).
"""

from pathlib import Path
import fitz

OUT_DIR = (
    Path(__file__).resolve().parent.parent / "spec" / "v1" / "testvectors" / "pdf-extraction"
)
OUT_DIR.mkdir(parents=True, exist_ok=True)

# Final Draft-convention column positions (in points; 72 per inch).
# Origin in PyMuPDF is TOP-left; y increases downward.
X_ACTION = 1.5 * 72       # 108
X_DIALOGUE = 2.9 * 72     # 208.8
X_PARENTHETICAL = 3.4 * 72  # 244.8
X_CHARACTER = 4.2 * 72    # 302.4
X_TRANSITION = 6.0 * 72   # 432.0
Y_TOP = 1.0 * 72          # 72
LINE_HEIGHT = 12          # 12pt courier

PAGE_WIDTH = 612          # 8.5 in
PAGE_HEIGHT = 792         # 11 in


def y(line_index):
    return Y_TOP + (line_index - 1) * LINE_HEIGHT


def write_line(page, line_index, x, text):
    page.insert_text(
        (x, y(line_index)),
        text,
        fontname="cour",
        fontsize=12,
    )


def make_minimal():
    path = OUT_DIR / "fixture-01-minimal.pdf"
    doc = fitz.open()
    page = doc.new_page(width=PAGE_WIDTH, height=PAGE_HEIGHT)

    write_line(page, 1, X_ACTION, "FADE IN:")
    write_line(page, 3, X_ACTION, "INT. KITCHEN - DAY")
    write_line(page, 5, X_ACTION, "A WRITER sits at a wooden table, staring at a blank screen.")
    write_line(page, 7, X_ACTION, "Coffee steams in a chipped mug.")

    write_line(page, 9, X_CHARACTER, "WRITER")
    write_line(page, 10, X_PARENTHETICAL, "(quietly)")
    write_line(page, 11, X_DIALOGUE, "Just one good line. That's all I need.")

    write_line(page, 13, X_ACTION, "The screen blinks back.")

    write_line(page, 15, X_CHARACTER, "VOICE (O.S.)")
    write_line(page, 16, X_DIALOGUE, "You said that yesterday.")

    write_line(page, 18, X_TRANSITION, "CUT TO:")
    write_line(page, 20, X_ACTION, "EXT. ROOFTOP - NIGHT")
    write_line(page, 22, X_ACTION, "Stars overhead. The writer steps to the edge, notebook in hand.")
    write_line(page, 24, X_ACTION, "FADE OUT.")

    doc.save(str(path))
    doc.close()
    print(f"wrote {path}")


def make_no_text_layer():
    """
    No-text-layer PDF: drawn shapes only, no text run. Some PyMuPDF-produced
    PDFs that contain no text trigger pdf2json's XRef parser to error
    upstream — both EXTRACT_NO_TEXT_LAYER and EXTRACT_CORRUPTED are
    acceptable rejection codes for this fixture (the contract is "reject
    loudly with a typed error", not "use one specific code").
    """
    path = OUT_DIR / "fixture-02-no-text-layer.pdf"
    doc = fitz.open()
    page = doc.new_page(width=PAGE_WIDTH, height=PAGE_HEIGHT)
    page.draw_rect(fitz.Rect(100, 100, 500, 700), color=(0, 0, 0))
    doc.save(str(path))
    doc.close()
    print(f"wrote {path}")


def make_corrupted():
    path = OUT_DIR / "fixture-03-corrupted.pdf"
    path.write_bytes(b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n")
    print(f"wrote {path}")


if __name__ == "__main__":
    make_minimal()
    make_no_text_layer()
    make_corrupted()
