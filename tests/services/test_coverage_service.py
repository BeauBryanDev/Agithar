from dataclasses import dataclass

import pytest

from app.services import coverage_service as svc


@dataclass
class Row:
    verdict: object


@pytest.mark.parametrize(
    "verdict, expected",
    [
        ({"verdict": "confirmed", "mitre_technique": "T1190"}, "T1190"),
        ({"verdict": "false_positive", "mitre_technique": "T1190"}, None),
        ({"verdict": "confirmed", "mitre_technique": "T１１９０"}, None),
        ({"verdict": "needs_human"}, None),
        ("not a dict", None),
        (None, None),
    ],
)
def test_confirmed_technique(verdict, expected):
    assert svc.confirmed_technique(Row(verdict)) == expected
