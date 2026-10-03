import re
from dataclasses import dataclass

# Terminal sessions and logs must be kept verbatim: reflowing them would
# destroy the meaning. Detection is a heuristic, tuned on the real books.
PROMPT_LINE = re.compile(
    r"^\s*(?:[\w.-]+@[\w.-]+[:~/\w.-]*\s?[#$>]|kali\S*\s?[#$>]|[$#>]\s)"
)
CAPTION_LINE = re.compile(r"^\s*Listing \d+-\d+[:.]", re.IGNORECASE)
LOG_HINT = re.compile(
    r"\b\d{1,2}:\d{2}:\d{2}\b"
    r"|\b\d{1,3}(?:\.\d{1,3}){3}\b"
    r"|\[\*\*\]"
    r"|\b0x[0-9a-fA-F]{2,}\b"
)
CODE_CHARS = set("{}[]<>|\\=*$#@&%^~_+")
MIN_CODE_LINE_CHARS = 6
CODE_CHAR_RATIO = 0.10
LOG_DIGIT_RATIO = 0.20
MIN_RUN_LINES = 2
SENTENCE_MIN_CHARS = 55
SENTENCE_MIN_WORDS = 8
SENTENCE_MAX_DIGIT_RATIO = 0.10
SENTENCE_MAX_CODE_RATIO = 0.03
SENTENCE_MIN_WORD_RATIO = 0.85
WORD_PUNCT = ".,;:()\"'’“”"


@dataclass(frozen=True)
class Block:
    kind: str
    text: str


def char_ratio(line: str, chars: set[str]) -> float:
    visible = [char for char in line if not char.isspace()]

    if not visible:
        return 0.0

    return sum(1 for char in visible if char in chars) / len(visible)


def digit_ratio(line: str) -> float:
    visible = [char for char in line if not char.isspace()]

    if not visible:
        return 0.0

    return sum(1 for char in visible if char.isdigit()) / len(visible)


def is_prompt_line(line: str) -> bool:
    return PROMPT_LINE.match(line) is not None


def is_code_like(line: str) -> bool:
    if is_prompt_line(line):
        return True

    if len(line.strip()) < MIN_CODE_LINE_CHARS:
        return False

    if char_ratio(line, CODE_CHARS) >= CODE_CHAR_RATIO:
        return True

    return LOG_HINT.search(line) is not None and (
        digit_ratio(line) >= LOG_DIGIT_RATIO
    )


def word_ratio(tokens: list[str]) -> float:
    words = [token for token in tokens if token.strip(WORD_PUNCT).isalpha()]

    return len(words) / len(tokens)


def is_sentence_line(line: str) -> bool:
    text = line.strip()

    if len(text) < SENTENCE_MIN_CHARS:
        return False

    tokens = text.split()

    if len(tokens) < SENTENCE_MIN_WORDS:
        return False

    if word_ratio(tokens) < SENTENCE_MIN_WORD_RATIO:
        return False

    if digit_ratio(text) > SENTENCE_MAX_DIGIT_RATIO:
        return False

    return char_ratio(text, CODE_CHARS) <= SENTENCE_MAX_CODE_RATIO


def extend_run(run: tuple[int, int], lines: list[str]) -> tuple[int, int]:
    # Command output follows its prompt line until the text turns to prose.
    start, end = run

    if not any(is_prompt_line(line) for line in lines[start:end]):
        return run

    while end < len(lines) and not is_sentence_line(lines[end]):
        end += 1

    return start, end


def code_runs(flags: list[bool], 
              lines: list[str]) -> list[tuple[int, int]]:
    runs = []
    start = None

    for index, flag in enumerate(flags + [False]):
        if flag and start is None:
            start = index

        if not flag and start is not None:
            runs.append((start, index))
            start = None

    kept = [run for run in runs if is_listing_run(run, lines)]

    return merge_runs([extend_run(run, lines) for run in kept])


def merge_runs(runs: list[tuple[int, int]]) -> list[tuple[int, int]]:
    merged: list[tuple[int, int]] = []

    for start, end in runs:
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(end, merged[-1][1]))
        else:
            merged.append((start, end))

    return merged


def is_listing_run(run: tuple[int, int], 
                   lines: list[str]
                   ) -> bool:
    start, end = run

    if end - start >= MIN_RUN_LINES:
        return True

    return any(is_prompt_line(line) for line in lines[start:end])


def split_group(lines: list[str]) -> list[Block]:
    flags = [is_code_like(line) for line in lines]
    blocks = []
    position = 0

    for start, end in code_runs(flags, lines):
        # A caption directly above a listing belongs to the listing.
        if start > position and CAPTION_LINE.match(lines[start - 1]):
            start -= 1

        if start > position:
            blocks.append(Block("prose", "\n".join(lines[position:start])))

        blocks.append(Block("listing", "\n".join(lines[start:end])))
        position = end

    if position < len(lines):
        blocks.append(Block("prose", "\n".join(lines[position:])))

    return blocks


def split_blocks(text: str) -> list[Block]:
    blocks = []
    group: list[str] = []

    for line in text.split("\n") + [""]:
        if line.strip():
            group.append(line.rstrip())
            continue

        if group:
            blocks.extend(split_group(group))
            group = []

    return blocks
