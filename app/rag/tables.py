import re
from collections import Counter

# A table has columns that start at the same horizontal position on many
# rows. Prose does not, so the count of aligned columns separates them.
GAP_BEFORE_TOKEN = re.compile(r"(?<=\S) {3,}(?=\S)")
MIN_GAP_COLUMN = 10
MIN_ROWS_PER_COLUMN = 4
MERGE_DISTANCE = 1
TABLE_MIN_COLUMNS = 1


def gap_columns(line: str) -> set[int]:
    columns = set()

    for match in GAP_BEFORE_TOKEN.finditer(line):
        if match.end() >= MIN_GAP_COLUMN:
            columns.add(match.end())

    return columns


def count_aligned_columns(layout_text: str) -> int:
    counts: Counter[int] = Counter()

    for line in layout_text.splitlines():
        if line.strip():
            counts.update(gap_columns(line.rstrip()))

    frequent = sorted(
        column
        for column, rows in counts.items()
        if rows >= MIN_ROWS_PER_COLUMN
    )

    merged: list[int] = []

    for column in frequent:
        if not merged or column - merged[-1] > MERGE_DISTANCE:
            merged.append(column)

    return len(merged)


def is_table_page(layout_text: str) -> bool:
    return count_aligned_columns(layout_text) >= TABLE_MIN_COLUMNS
