"""Do the relevance tests still have teeth?

A passing suite proves nothing on its own — it may be passing because the code
is right, or because the tests cannot tell the difference. Every relevance bug
found so far passed a green suite first.

So this reintroduces each historical bug, one at a time, and asserts the corpus
suite FAILS. A mutation that survives means the test that was supposed to guard
it is decorative, and the next regression of that kind ships silently.

This already earned itself twice while being written:

  * mutating the word-boundary rule was survived, because the same rule was
    written out in two functions and the untouched copy held the line. Fixed by
    making one define the other — the duplication was the real defect.
  * the CJK name-order rule had no failing case at all: every existing test put
    the target's full name in the document verbatim, which short-circuits on
    the exact-string path before the name-order logic ever runs.

Adding a mutation is one row in MUTATIONS.
"""

import importlib.util
import os
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import blacknoir.entities as E

_CORPUS = Path(__file__).parent / "test_relevance_corpus.py"

_orig_significant = E._significant_tokens


def _substring_spans(token, hay):
    """The pre-fix behaviour: 'yi' matches inside 'Yiu'."""
    return [m.start() for m in re.finditer(re.escape(token), hay)] if token else []


def _two_token_names(text):
    """The pre-fix behaviour: only ever consider a 2-token name, so the
    surname-first (lead_ok) path cannot fire."""
    toks = _orig_significant(text)
    return toks[:2] if len(toks) > 2 else toks


# label -> (attribute, replacement)
MUTATIONS = {
    "no proximity requirement (the drama-page bug)":
        ("_co_occur", lambda tokens, hay, window=60: True),
    "substring instead of word-boundary ('yi' inside 'Yiu')":
        ("_token_spans", _substring_spans),
    "surname assumed to be the LAST token (breaks CJK name order)":
        ("_significant_tokens", _two_token_names),
    "generic geography counts as corroborating context":
        ("_GENERIC_CONTEXT", set()),
}


def _run_corpus() -> int:
    """Run the relevance corpus suite; return failure+error count."""
    spec = importlib.util.spec_from_file_location("_relcorpus", _CORPUS)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    suite = unittest.TestLoader().loadTestsFromModule(mod)
    with open(os.devnull, "w") as devnull:
        result = unittest.TextTestRunner(verbosity=0, stream=devnull).run(suite)
    return len(result.failures) + len(result.errors)


class TestSuiteHasTeeth(unittest.TestCase):
    def setUp(self):
        self._saved = {attr: getattr(E, attr)
                       for attr, _ in MUTATIONS.values()}

    def tearDown(self):
        for attr, original in self._saved.items():
            setattr(E, attr, original)

    def test_corpus_passes_unmutated(self):
        """Baseline: with every fix in place the corpus must be green."""
        self.assertEqual(_run_corpus(), 0,
                         "corpus suite fails before any mutation is applied")

    def test_every_known_bug_is_caught(self):
        for label, (attr, replacement) in MUTATIONS.items():
            with self.subTest(mutation=label):
                for a, original in self._saved.items():
                    setattr(E, a, original)
                setattr(E, attr, replacement)
                failures = _run_corpus()
                self.assertGreater(
                    failures, 0,
                    f"MUTATION SURVIVED — nothing fails when '{label}' is "
                    f"reintroduced, so that guard is decorative")


if __name__ == "__main__":
    unittest.main()
