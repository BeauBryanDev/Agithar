import re
from dataclasses import dataclass

from app.rag.clean import CleanPage
from app.rag.tokens import count_tokens, split_by_tokens

CHUNK_TOKENS = 512
LISTING_MAX_TOKENS = 2000
SENTENCE_BREAK = re.compile(r'(?<=[.!?])\s+(?=[A-Z0-9"“(\[])')
SENTENCE_END = ".!?:;)\"”’"
PARAGRAPH_JOIN = "\n"
SENTENCE_JOIN = " "
BLOCK_JOIN = "\n\n"


@dataclass(frozen=True)
class Piece:
    kind: str
    text: str
    joiner: str
    page_start: int
    page_end: int
    tokens: int
    atomic: bool


@dataclass
class Unit:
    kind: str
    text: str
    page_start: int
    page_end: int


def continues_previous(units: list[Unit], 
                       kind: str, 
                       text: str, 
                       page: int):
    # A paragraph that runs over a page break is one paragraph.
    if not units or kind != "prose":
        return False

    last = units[-1]

    if last.kind != "prose" or last.page_end != page - 1:
        return False

    return last.text[-1] not in SENTENCE_END and text[:1].islower()


def section_units(pages: list[CleanPage]) -> list[Unit]:
    units: list[Unit] = []

    for page in pages:
        for block in page.blocks:
            text = block.text.strip()

            if not text:
                continue

            if continues_previous(units, block.kind, 
                                  text, 
                                  page.page
                                  ):
                units[-1].text += SENTENCE_JOIN + text
                units[-1].page_end = page.page
            else:
                units.append(Unit(block.kind, 
                                  text, 
                                  page.page, 
                                  page.page)
                             )

    return units


def make_piece(unit: Unit, 
               text: str, 
               joiner: str, 
               atomic: bool
               ) -> Piece:
    
    return Piece(
        kind=unit.kind,
        text=text,
        joiner=joiner,
        page_start=unit.page_start,
        page_end=unit.page_end,
        tokens=count_tokens(text),
        atomic=atomic,
    )


def sentence_pieces(unit: Unit, 
                    sentence: str, 
                    joiner: str
                    ) -> list[Piece]:
    
    if count_tokens(sentence) <= CHUNK_TOKENS:
        
        return [make_piece(unit, 
                           sentence, 
                           joiner, 
                           False)
                ]

    pieces = []

    for index, part in enumerate(split_by_tokens(sentence, CHUNK_TOKENS)):
        
        part_joiner = joiner if index == 0 else ""
        pieces.append(make_piece(unit, part, part_joiner, False))

    return pieces


def prose_pieces(unit: Unit) -> list[Piece]:
    pieces = []

    for paragraph in unit.text.split("\n"):
        sentences = SENTENCE_BREAK.split(paragraph.strip())

        for index, sentence in enumerate(sentences):
            if not sentence.strip():
                continue

            joiner = PARAGRAPH_JOIN if index == 0 else SENTENCE_JOIN
            pieces.extend(sentence_pieces(unit, sentence.strip(), joiner))

    return pieces


def line_groups(text: str, limit: int) -> list[str]:
    groups = []
    current: list[str] = []
    used = 0

    for line in text.split("\n"):
        cost = count_tokens(line) + 1

        if current and used + cost > limit:
            groups.append("\n".join(current))
            current, used = [], 0

        if cost > limit:
            groups.extend(split_by_tokens(line, limit))
            continue

        current.append(line)
        used += cost

    if current:
        groups.append("\n".join(current))

    return groups


def block_pieces(unit: Unit, limit: int) -> list[Piece]:
    # Listings and tables are never overlapped: they are atomic pieces.
    groups = line_groups(unit.text, limit)

    return [make_piece(unit, group, BLOCK_JOIN, True) for group in groups]


def unit_pieces(unit: Unit) -> list[Piece]:
    if unit.kind == "prose":
        return prose_pieces(unit)

    if unit.kind == "listing":
        if count_tokens(unit.text) <= LISTING_MAX_TOKENS:
            return [make_piece(unit, unit.text, BLOCK_JOIN, True)]

        return block_pieces(unit, LISTING_MAX_TOKENS)

    return block_pieces(unit, CHUNK_TOKENS)


def section_pieces(pages: list[CleanPage]) -> list[Piece]:
    pieces = []

    for unit in section_units(pages):
        pieces.extend(unit_pieces(unit))

    return pieces
