"""Relevance-gate testing against LONG and ADVERSARIAL documents.

WHY THIS FILE EXISTS
--------------------
Every relevance bug found so far shared one root cause, and it was not in the
matcher — it was in the fixtures. Short strings, invented to match whatever
mental model was being tested, cannot exhibit the failure mode that real pages
have:

    In a long enough document, EVERY common token appears somewhere.

A 20,000-character inter-school competition page carrying dozens of people
contains "Wong" and "Yi" many times over — in other people's names. A matcher
that only asks "is this token present?" says yes, and a stranger's prize
listing becomes evidence about a specific teenager. A 40-character fixture
never reveals that; the bug is a function of document length.

So this file tests two things a short fixture cannot:

  1. LONG CORPUS - full-length pages stored in fixtures/noise_pages.json,
     shaped like the real ones that caused the bug. Add a row to CORPUS below.

     NOTE: these fixtures are SYNTHETIC BY POLICY. The page that originally
     exposed this bug was a live capture naming dozens of primary-school
     children with their class codes. Reproducing the adversarial *shape* —
     length, name density, surname collisions — is what the test needs; the
     real children are not. Never commit a scraped page that names real
     people, least of all minors. Generate an equivalent instead.

  2. ADVERSARIAL SCALE - documents generated with a growing number of OTHER
     people's names, asserting the verdict does not flip as noise grows. This
     is the invariant that generalises past any specific page:

         A document that does not contain the target's name is never about the
         target, no matter how long it is or how many other names it holds.

Adding a case is one row, not a new test.
"""

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from blacknoir.entities import is_about_target

FIXTURES = Path(__file__).parent / "fixtures" / "noise_pages.json"

TARGET = "Wong Jing Yi"
CONTEXT = "+852 5550 0100 高蕾中學 Hong Kong"
ALIASES = ["王婧妍"]

# --- real pages ------------------------------------------------------------
# (fixture key, expected is_about_target verdict, why)
CORPUS = [
    ("drama2025", False,
     "inter-school drama competition results: ~35 other people's names, "
     "'Wong' as a surname 43x and 'Yi' as a syllable 27x, never the target "
     "and never the target's school"),
]

# Surnames/given names common enough to appear on any Hong Kong school page.
_FILLER_NAMES = [
    "Wong Ka Ming", "Chan Yiu Fai", "Lee Ying Wah", "Cheung Yi Lam",
    "Ho Jing Wai", "Lam Wong Kit", "Ng Yi Ching", "Tsang Ka Yi",
    "Yeung Jing Hei", "Chow Wong Man", "Lau Yi Tung", "Kwok Jing Yan",
]
_FILLER_ORGS = [
    "Hong Kong Secondary School", "Kowloon College", "New Territories School",
    "Hong Kong Baptist College", "Sha Tin Government Secondary School",
]


def noise_document(n_names: int, include_target: bool = False,
                   target: str = TARGET) -> str:
    """A plausible long page full of OTHER people, optionally naming the target.

    Deliberately built from the tokens that break naive matching: names sharing
    the target's surname and syllables, plus the geography that shows up in the
    target's own disambiguating context.
    """
    parts = ["Interschool Competition Results 2025 Hong Kong"]
    for i in range(n_names):
        person = _FILLER_NAMES[i % len(_FILLER_NAMES)]
        org = _FILLER_ORGS[i % len(_FILLER_ORGS)]
        parts.append(f"{i + 1}. {person} — {org}, Hong Kong. Award: Merit.")
    if include_target:
        parts.insert(len(parts) // 2,
                     f"Champion: {target} — 高蕾中學, Hong Kong.")
    return " ".join(parts)


class TestRealCorpus(unittest.TestCase):
    """Pages actually fetched from the web, stored offline."""

    @classmethod
    def setUpClass(cls):
        cls.pages = (json.loads(FIXTURES.read_text(encoding="utf-8"))
                     if FIXTURES.exists() else {})

    def test_fixtures_present(self):
        self.assertTrue(self.pages, f"missing fixture file: {FIXTURES}")

    def test_corpus_verdicts(self):
        for key, expected, why in CORPUS:
            page = self.pages.get(key)
            self.assertIsNotNone(page, f"fixture {key!r} not captured")
            blob = f"{page.get('title', '')} {page['text']} {page.get('url', '')}"
            got = is_about_target(blob, TARGET, CONTEXT, ALIASES)
            self.assertEqual(got, expected, f"{key}: {why}")

    def test_corpus_pages_are_actually_long(self):
        """Guards the guard: a fixture truncated to nothing proves nothing."""
        for key, _, _ in CORPUS:
            self.assertGreater(len(self.pages[key]["text"]), 2000,
                               f"{key} fixture is too short to be adversarial")


class TestAdversarialScale(unittest.TestCase):
    """The invariant that generalises beyond the pages we happened to hit."""

    SIZES = (1, 5, 25, 100, 400)

    def test_noise_never_becomes_a_match(self):
        """No amount of other people's names makes a page about the target."""
        for n in self.SIZES:
            doc = noise_document(n)
            self.assertFalse(
                is_about_target(doc, TARGET, CONTEXT, ALIASES),
                f"{n} filler names ({len(doc)} chars) produced a false match")

    def test_verdict_does_not_flip_with_length(self):
        """A true match stays a match, and a non-match stays a non-match."""
        for n in self.SIZES:
            self.assertTrue(
                is_about_target(noise_document(n, include_target=True),
                                TARGET, CONTEXT, ALIASES),
                f"target named but lost among {n} filler names")

    def test_alias_survives_noise(self):
        doc = noise_document(200).replace(
            "Interschool", "中二級家長晚會 王婧妍 2A 高蕾中學 Interschool", 1)
        self.assertTrue(is_about_target(doc, TARGET, CONTEXT, ALIASES))

    def test_scattered_tokens_are_not_a_name(self):
        """The exact drama-page failure, reduced to its essence."""
        doc = ("Wong Ka Ming won first prize. " + "filler text " * 200
               + " Chan Tsz Yi received merit.")
        self.assertFalse(is_about_target(doc, TARGET, CONTEXT, ALIASES),
                         "'Wong' and 'Yi' from two different people matched")

    def test_adjacent_tokens_from_two_people_are_not_a_name(self):
        """Hardest case: the syllables are adjacent but belong to two people."""
        doc = "Prize list: Wong Ka Ming, Chan Tsz Yi, Lee Ho Man. Hong Kong."
        self.assertFalse(is_about_target(doc, TARGET, CONTEXT, ALIASES))

    def test_generic_geography_cannot_corroborate(self):
        """'Hong Kong' is on every HK page and must not confirm anything."""
        doc = "Wong Ka Ming, a student in Hong Kong, won an award. " * 40
        self.assertFalse(is_about_target(doc, TARGET, CONTEXT, ALIASES))

    def test_syllable_inside_a_longer_word_is_not_the_token(self):
        """'yi' is a substring of 'Yiu'/'Ying'/'Yip' — all common HK names.

        Written so PROXIMITY alone cannot save it: the lookalike syllable sits
        right next to the real school name, so only word-boundary matching
        rejects this. Verified by mutation: swapping `_token_present` back to
        substring matching makes exactly this test fail.
        """
        for lookalike in ("Chan Yiu Ming", "Lee Ying Wah", "Ho Yip Cheung"):
            doc = f"{lookalike}, 高蕾中學, won the merit award."
            self.assertFalse(
                is_about_target(doc, TARGET, CONTEXT, ALIASES),
                f"'{lookalike}' matched the 'yi' token as a substring")

    def test_surname_lookalike_is_not_the_surname(self):
        doc = "Wongchai Prasert, 高蕾中學 exchange visit."
        self.assertFalse(is_about_target(doc, TARGET, CONTEXT, ALIASES))

    def test_cjk_name_order_partial_match(self):
        """Surname-FIRST partial match, without the full name appearing.

        Covers the path that assuming "surname == last token" broke: for
        "Wong Jing Yi" that assumption demanded "yi", the least distinctive
        syllable, while the family name sat in position 0. Deliberately avoids
        writing the name in full, or the exact-string fast path would answer
        before this logic ever runs.
        """
        doc = ("Congratulations to Wong Jing of 高蕾中學 on the robotics prize. "
               + "other results " * 50)
        self.assertTrue(is_about_target(doc, TARGET, CONTEXT, ALIASES),
                        "surname-first partial match was rejected")

    def test_cjk_partial_still_needs_two_tokens(self):
        """A bare shared surname is not a partial match, even beside context."""
        doc = "Wong of 高蕾中學 attended. " + "filler " * 50
        self.assertFalse(is_about_target(doc, TARGET, CONTEXT, ALIASES))


class TestWesternNameRegressions(unittest.TestCase):
    """The same scale hazard for the two-token Western case."""

    def test_shared_first_name_at_scale(self):
        doc = ("AI security podcast archive. "
               + "Episode with Alex Bell on threat modeling. " * 60)
        self.assertFalse(is_about_target(doc, "Alex Marsh", "AI security"))

    def test_surname_plus_context_still_matches_at_scale(self):
        doc = ("conference programme " * 100
               + " Marsh presenting AI security research " + "footer " * 100)
        self.assertTrue(is_about_target(doc, "Alex Marsh", "AI security"))


if __name__ == "__main__":
    unittest.main()
