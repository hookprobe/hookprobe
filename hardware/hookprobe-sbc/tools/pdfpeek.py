"""Small helper for reading reference PDFs: page index, text search, cropped renders.

    pdfpeek.py index FILE
    pdfpeek.py find FILE TERM [TERM...]
    pdfpeek.py crop FILE PAGE X0 Y0 X1 Y1 OUT.png [ZOOM]     (page is 1-based, coordinates in PDF points)
    pdfpeek.py words FILE PAGE X0 Y0 X1 Y1
"""
import sys

import fitz  # PyMuPDF


def main():
    cmd, path = sys.argv[1], sys.argv[2]
    doc = fitz.open(path)
    if cmd == "index":
        for i, page in enumerate(doc, start=1):
            words = [w[4] for w in page.get_text("words")]
            big = sorted(set(w for w in words if len(w) > 9 and w.isupper()))[:6]
            print("p%-3d %4.0fx%-4.0f words=%-5d %s" % (i, page.rect.width, page.rect.height, len(words), " ".join(big)))
    elif cmd == "find":
        for term in sys.argv[3:]:
            for i, page in enumerate(doc, start=1):
                for w in page.get_text("words"):
                    if term.lower() in w[4].lower():
                        print("%-22s p%-3d (%.0f, %.0f)  %s" % (term, i, w[0], w[1], w[4]))
    elif cmd == "crop":
        page = doc[int(sys.argv[3]) - 1]
        clip = fitz.Rect(*[float(v) for v in sys.argv[4:8]]) & page.rect
        zoom = float(sys.argv[9]) if len(sys.argv) > 9 else 3.0
        page.get_pixmap(matrix=fitz.Matrix(zoom, zoom), clip=clip).save(sys.argv[8])
        print("saved", sys.argv[8], clip)
    elif cmd == "words":
        page = doc[int(sys.argv[3]) - 1]
        clip = fitz.Rect(*[float(v) for v in sys.argv[4:8]])
        for w in sorted(page.get_text("words", clip=clip), key=lambda w: (round(w[1] / 6), w[0])):
            print("(%.0f, %.0f) %s" % (w[0], w[1], w[4]))


if __name__ == "__main__":
    main()
