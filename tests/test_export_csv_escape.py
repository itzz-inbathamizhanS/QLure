"""CSV export neutralises spreadsheet formulas in attacker-controlled cells."""

from __future__ import annotations

import csv
import io
from datetime import UTC, datetime

import pytest

from qlure import export as ioc_export

WHEN = datetime(2026, 1, 1, tzinfo=UTC)


def _rows(*values: str) -> list[list[str]]:
    inds = [ioc_export.Indicator("user-agent", v, WHEN, WHEN) for v in values]
    data = ioc_export.Export("noteworthy", [], inds)
    return list(csv.reader(io.StringIO(ioc_export.csv_text(data))))[1:]


@pytest.mark.parametrize(
    "value",
    ['=HYPERLINK("http://x","y")', "+1+1", "-2", "@SUM(A1)", "\tx", "\rx"],
)
def test_formula_cells_are_prefixed(value):
    assert _rows(value)[0][1] == "'" + value


def test_normal_values_are_unchanged():
    row = _rows("Mozilla/5.0", "/a/b", "203.0.113.5", "a" * 64)
    assert [r[1] for r in row] == ["Mozilla/5.0", "/a/b", "203.0.113.5", "a" * 64]
    assert row[0][4] == "0"
