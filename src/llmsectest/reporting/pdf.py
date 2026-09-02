"""A PDF writer built on the standard library, so a security tool gains no dependency.

The blog post promises reports in SARIF, HTML and PDF. Two of those three shipped; this
is the third, and it exists under one constraint that shaped every decision in it: **a
tool people run against their own security-critical systems may not grow a rendering
stack.** Core install is `pytest` and nothing else, the SBOM writer, the model-file scan
and the vector-store scan are all standard library only, and a PDF exporter that pulled in
a browser or a font toolchain would be the largest dependency in the tree by an order of
magnitude, added for a cosmetic output.

**So this writes PDF directly.** That is affordable because of one property of the format:
every conforming reader ships the 14 standard Type1 fonts, so a document that asks for
Helvetica, Helvetica-Bold or Courier embeds no font programme at all and stays a few
kilobytes. What it costs is that we must know the glyph widths ourselves to wrap a line,
which is the width tables below, measured constants from Adobe's own metrics rather than
guesses.

**What this is not.** It is not an HTML converter and does not try to be. Converting the
HTML report would mean a layout engine, which is the dependency this module exists to
avoid. It reads the same SARIF the HTML reader reads, so the two describe one run from one
source, and it lays that out for paper.

**The honesty properties travel with the content.** A report that showed findings while
dropping the inconclusive and undelivered counts would be this project's own defect class
in a new file format, so those are rendered before the findings rather than after, and a
run that could not deliver its probes says so on page one.
"""

from __future__ import annotations

import zlib
from dataclasses import dataclass, field

#: Page geometry in PDF points (1/72 inch). A4, because the funder, the reader and the
#: author are all in Europe.
PAGE_WIDTH = 595.28
PAGE_HEIGHT = 841.89
MARGIN = 56.7  # 20mm

#: Glyph widths per 1000 units for the standard fonts we use, from Adobe's metrics for
#: the Type1 base 14. Needed because wrapping is ours to do: the reader supplies the font
#: and we must predict what it will draw. Courier is monospaced, so it needs no table.
_HELVETICA = (
    "278 278 355 556 556 889 667 191 333 333 389 584 278 333 278 278 "
    "556 556 556 556 556 556 556 556 556 556 278 278 584 584 584 556 "
    "1015 667 667 722 722 667 611 778 722 278 500 667 556 833 722 778 "
    "667 778 722 667 611 722 667 944 667 667 611 278 278 278 469 556 "
    "333 556 556 500 556 556 278 556 556 222 222 500 222 833 556 556 "
    "556 556 333 500 278 556 500 722 500 500 500 334 260 334 584"
)
_HELVETICA_BOLD = (
    "278 333 474 556 556 889 722 238 333 333 389 584 278 333 278 278 "
    "556 556 556 556 556 556 556 556 556 556 333 333 584 584 584 611 "
    "975 722 722 722 722 667 611 778 722 278 556 722 611 833 722 778 "
    "667 778 722 667 611 722 667 944 667 667 611 333 278 333 584 556 "
    "333 556 611 556 611 556 333 611 611 278 278 556 278 889 611 611 "
    "611 611 389 556 333 611 556 778 556 556 500 389 280 389 584"
)


def _widths(table: str) -> list[int]:
    return [int(w) for w in table.split()]


_WIDTHS = {
    "Helvetica": _widths(_HELVETICA),
    "Helvetica-Bold": _widths(_HELVETICA_BOLD),
}
#: Every Courier glyph is this wide. The whole point of a monospaced face.
_COURIER_WIDTH = 600


def text_width(text: str, font: str, size: float) -> float:
    """Width of ``text`` in points, as the reader will actually draw it.

    Characters outside the table fall back to the width of ``n``, which is close to the
    average for Latin text. A wrong width here costs a ragged margin rather than a
    corrupt file, so the fallback is deliberately unexciting.
    """
    if font.startswith("Courier"):
        return len(text) * _COURIER_WIDTH * size / 1000.0
    table = _WIDTHS.get(font, _WIDTHS["Helvetica"])
    fallback = table[ord("n") - 32]
    total = 0
    for ch in text:
        code = ord(ch)
        total += table[code - 32] if 32 <= code <= 126 else fallback
    return total * size / 1000.0


def wrap(text: str, font: str, size: float, width: float) -> list[str]:
    """Greedy word wrap against the real glyph widths.

    A word longer than the line (a URL, a base64 blob, a canary) is broken by character
    rather than allowed to run off the page, because in this report those are exactly the
    strings a reader needs to see in full.
    """
    lines: list[str] = []
    for paragraph in text.split("\n"):
        if not paragraph.strip():
            lines.append("")
            continue
        current = ""
        for word in paragraph.split():
            candidate = f"{current} {word}".strip()
            if text_width(candidate, font, size) <= width:
                current = candidate
                continue
            if current:
                lines.append(current)
            while text_width(word, font, size) > width:
                cut = len(word)
                while cut > 1 and text_width(word[:cut], font, size) > width:
                    cut -= 1
                lines.append(word[:cut])
                word = word[cut:]
            current = word
        if current:
            lines.append(current)
    return lines


def _pdf_escape(text: str) -> str:
    """Escape a string for a PDF literal, and drop what the base fonts cannot draw.

    The standard fonts are single-byte, so a non-Latin-1 character has no glyph and would
    render as a wrong one. Replacing it with ``?`` is visibly lossy, which is the point:
    silently emitting a different character in a security report is worse than showing
    that something was dropped.
    """
    out = []
    for ch in text:
        if ch in "()\\":
            out.append("\\" + ch)
        elif 32 <= ord(ch) <= 126:
            out.append(ch)
        elif ch in "‘’":
            out.append("'")
        elif ch in "“”":
            out.append('"')
        elif ch in "–—":
            out.append("-")
        elif ch == "→":
            out.append("->")
        elif 160 <= ord(ch) <= 255:
            out.append(f"\\{ord(ch):03o}")
        else:
            out.append("?")
    return "".join(out)


@dataclass
class _Page:
    parts: list[str] = field(default_factory=list)

    def stream(self) -> bytes:
        return "\n".join(self.parts).encode("latin-1", "replace")


class PDFDocument:
    """A paginated text document. Positions are in points from the top-left.

    Deliberately small: text runs, wrapped paragraphs, horizontal rules and filled
    rectangles. Everything the report needs is one of those four, and anything richer
    would be the beginning of the layout engine this module exists to not have.
    """

    def __init__(self, title: str = "", author: str = ""):
        self.title = title
        self.author = author
        self._pages: list[_Page] = []
        self._page: _Page | None = None
        self.y = 0.0
        self.new_page()

    # ---- geometry -------------------------------------------------------------
    @property
    def content_width(self) -> float:
        return PAGE_WIDTH - 2 * MARGIN

    def new_page(self) -> None:
        self._page = _Page()
        self._pages.append(self._page)
        self.y = MARGIN

    def space(self, points: float) -> None:
        self.y += points

    def _ensure(self, needed: float) -> None:
        """Start a new page when ``needed`` points would cross the bottom margin."""
        if self.y + needed > PAGE_HEIGHT - MARGIN:
            self.new_page()

    # ---- drawing --------------------------------------------------------------
    def text(self, content: str, *, font: str = "Helvetica", size: float = 10,
             color: tuple[float, float, float] = (0, 0, 0), indent: float = 0) -> None:
        """One line, no wrapping. Callers that may overflow use :meth:`paragraph`."""
        self._ensure(size * 1.2)
        r, g, b = color
        self._page.parts.append(
            f"BT /{font} {size:.2f} Tf {r:.3f} {g:.3f} {b:.3f} rg "
            f"1 0 0 1 {MARGIN + indent:.2f} {PAGE_HEIGHT - self.y - size:.2f} Tm "
            f"({_pdf_escape(content)}) Tj ET"
        )
        self.y += size * 1.2

    def paragraph(self, content: str, *, font: str = "Helvetica", size: float = 10,
                  color: tuple[float, float, float] = (0, 0, 0), indent: float = 0,
                  leading: float = 1.35) -> None:
        width = self.content_width - indent
        for line in wrap(content, font, size, width):
            self._ensure(size * leading)
            if line:
                r, g, b = color
                self._page.parts.append(
                    f"BT /{font} {size:.2f} Tf {r:.3f} {g:.3f} {b:.3f} rg "
                    f"1 0 0 1 {MARGIN + indent:.2f} {PAGE_HEIGHT - self.y - size:.2f} Tm "
                    f"({_pdf_escape(line)}) Tj ET"
                )
            self.y += size * leading

    def rule(self, *, color: tuple[float, float, float] = (0.8, 0.8, 0.8),
             thickness: float = 0.5) -> None:
        self._ensure(thickness + 4)
        r, g, b = color
        top = PAGE_HEIGHT - self.y
        self._page.parts.append(
            f"{r:.3f} {g:.3f} {b:.3f} RG {thickness:.2f} w "
            f"{MARGIN:.2f} {top:.2f} m {PAGE_WIDTH - MARGIN:.2f} {top:.2f} l S"
        )
        self.y += thickness + 4

    def box(self, height: float, *, color: tuple[float, float, float],
            indent: float = 0) -> None:
        """A filled rectangle at the cursor. Used for severity chips and banners."""
        self._ensure(height)
        r, g, b = color
        self._page.parts.append(
            f"{r:.3f} {g:.3f} {b:.3f} rg "
            f"{MARGIN + indent:.2f} {PAGE_HEIGHT - self.y - height:.2f} "
            f"{self.content_width - indent:.2f} {height:.2f} re f"
        )

    # ---- serialisation --------------------------------------------------------
    def _font_objects(self, first: int) -> tuple[list[bytes], str]:
        names = ["Helvetica", "Helvetica-Bold", "Courier"]
        objects = [
            f"<< /Type /Font /Subtype /Type1 /BaseFont /{n} /Encoding /WinAnsiEncoding >>"
            .encode("latin-1")
            for n in names
        ]
        refs = " ".join(f"/{n} {first + i} 0 R" for i, n in enumerate(names))
        return objects, refs

    def build(self) -> bytes:
        """Serialise to a single-file PDF 1.4 document.

        Streams are deflated with :mod:`zlib`, which every reader supports and which is
        the difference between a 30 KB report and a 300 KB one on a long run.
        """
        objects: list[bytes] = []

        def add(body: bytes) -> int:
            objects.append(body)
            return len(objects)

        catalog_num = add(b"")           # 1, patched below
        pages_num = add(b"")             # 2, patched below
        font_first = len(objects) + 1
        font_objs, font_refs = self._font_objects(font_first)
        for obj in font_objs:
            add(obj)

        page_nums: list[int] = []
        for page in self._pages:
            raw = page.stream()
            data = zlib.compress(raw)
            content_num = add(
                b"<< /Length " + str(len(data)).encode() + b" /Filter /FlateDecode >>\n"
                b"stream\n" + data + b"\nendstream"
            )
            page_nums.append(add(
                f"<< /Type /Page /Parent {pages_num} 0 R "
                f"/MediaBox [0 0 {PAGE_WIDTH:.2f} {PAGE_HEIGHT:.2f}] "
                f"/Resources << /Font << {font_refs} >> >> "
                f"/Contents {content_num} 0 R >>".encode("latin-1")
            ))

        info_num = add(
            f"<< /Title ({_pdf_escape(self.title)}) /Author ({_pdf_escape(self.author)}) "
            f"/Producer (llmsectest) >>".encode("latin-1")
        )
        kids = " ".join(f"{n} 0 R" for n in page_nums)
        objects[pages_num - 1] = (
            f"<< /Type /Pages /Count {len(page_nums)} /Kids [{kids}] >>".encode("latin-1")
        )
        objects[catalog_num - 1] = (
            f"<< /Type /Catalog /Pages {pages_num} 0 R >>".encode("latin-1")
        )

        out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
        offsets = [0]
        for i, body in enumerate(objects, start=1):
            offsets.append(len(out))
            out += f"{i} 0 obj\n".encode() + body + b"\nendobj\n"
        xref_at = len(out)
        out += f"xref\n0 {len(objects) + 1}\n".encode()
        out += b"0000000000 65535 f \n"
        for off in offsets[1:]:
            out += f"{off:010d} 00000 n \n".encode()
        out += (
            f"trailer\n<< /Size {len(objects) + 1} /Root {catalog_num} 0 R "
            f"/Info {info_num} 0 R >>\nstartxref\n{xref_at}\n%%EOF\n".encode()
        )
        return bytes(out)
