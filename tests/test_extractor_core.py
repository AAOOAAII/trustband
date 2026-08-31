"""A value the source does not contain cannot be extracted (no model)."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from warrantable.extractor import resolve, Field
from warrantable.gate import Band

def test_only_substrings_survive():
    src = "Pay account UK12345678901234567890 the sum of 1450 pounds."
    schema = [Field("recipient", "account", max_len=40)]
    # a real value: located, admitted, banded TOOL
    i = src.find("UK12345678901234567890")
    got, missing = resolve(src, {"recipient": (i, i+22)}, schema)
    assert len(got) == 1 and got[0].value == "UK12345678901234567890"
    assert got[0].tainted().band is Band.TOOL
    # a fabricated value has no valid span in the source
    assert src.find("US133000000121212121212") == -1

if __name__ == "__main__":
    test_only_substrings_survive()
    print("  ok  only source substrings are extractable, banded TOOL")
