"""Offline unit tests for Black Noir — no network, no API keys required.

Run:  python -m unittest discover -s tests -v
   or  pytest -q
"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from blacknoir.guardrails import Guardrails, is_onion
from blacknoir.entities import classify_target, PATTERNS, correlate
from blacknoir.config import REGISTRY, sources_for_surface
from blacknoir.models import Investigation, SearchResult, SourceRun
from blacknoir.env import load_dotenv
from blacknoir.llm import LLM, SPECS, _vision_capable
from blacknoir.inputs import process_input_dir
from blacknoir.connectors import _looks_blocked, _parse_ddg, run_source
from blacknoir.http import Fetcher


class TestGuardrails(unittest.TestCase):
    def setUp(self):
        self.g = Guardrails()

    def test_onion_blocked(self):
        ok, reason = self.g.can_fetch("http://abcdefghij234567.onion/x")
        self.assertFalse(ok)
        self.assertEqual(reason, "onion-fetch-forbidden")

    def test_download_blocked(self):
        for u in ("https://ahmia.fi/a.exe", "https://ahmia.fi/b.zip"):
            self.assertFalse(self.g.can_fetch(u)[0])

    def test_scheme_blocked(self):
        self.assertFalse(self.g.can_fetch("ftp://ahmia.fi/x")[0])

    def test_offlist_host_blocked(self):
        self.assertFalse(self.g.can_fetch("https://randomhost.tld/x")[0])

    def test_allowlisted_ok(self):
        self.assertTrue(self.g.can_fetch("https://ahmia.fi/search/?q=z")[0])

    def test_summary_counts(self):
        self.g.can_fetch("https://ahmia.fi/search/?q=z")
        self.g.can_fetch("http://x.onion/y")
        s = self.g.summary()
        self.assertEqual(s["allowed"], 1)
        self.assertEqual(s["blocked"], 1)

    def test_is_onion(self):
        self.assertTrue(is_onion("abc.onion"))
        self.assertFalse(is_onion("example.com"))


class TestEntities(unittest.TestCase):
    def test_classify(self):
        self.assertEqual(classify_target("a@b.com"), "email")
        self.assertEqual(classify_target("@handle_x"), "username")
        self.assertEqual(classify_target("example.com"), "domain")
        self.assertEqual(classify_target("John Smith"), "name")
        self.assertEqual(classify_target("1.2.3.4"), "ip")

    def test_patterns(self):
        text = ("mail me a@b.com, btc 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa "
                "onion abcdefghij234567.onion handle @nightowl_x")
        self.assertTrue(PATTERNS["email"].search(text))
        self.assertTrue(PATTERNS["btc"].search(text))
        self.assertTrue(PATTERNS["onion"].search(text))
        self.assertTrue(PATTERNS["handle"].search(text))

    def test_correlate_builds_graph(self):
        inv = Investigation(target="a@b.com", target_type="email",
                            surfaces=["public"], started="now")
        inv.runs.append(SourceRun(
            "bing", "Bing", "public", "ok",
            results=[SearchResult("bing", "public", "hit",
                                  snippet="see @nightowl_x and c@d.com")]))
        correlate(inv)
        kinds = {e.kind for e in inv.entities}
        self.assertIn("email", kinds)
        self.assertIn("handle", kinds)
        # target is always present with the highest weight
        self.assertEqual(inv.entities[0].value, "a@b.com")
        self.assertTrue(len(inv.edges) >= 1)


class TestContextRetention(unittest.TestCase):
    """The disambiguating qualifier must reach the queries, not just the report.

    Regression guard for the failure that made a findable person look absent:
    '"Alex Marsh" who is from AI Security Industry' was parsed down to the bare
    name, so every query searched a name shared by 100+ people.
    """

    def test_quoted_subject_and_trailing_context(self):
        from blacknoir.intent import heuristic_parse
        p = heuristic_parse('"Alex Marsh" who is from AI Security Industry')
        self.assertEqual(p["subject"], "Alex Marsh")
        self.assertIn("ai security", p["context"].lower())

    def test_unquoted_from_clause(self):
        from blacknoir.intent import heuristic_parse
        p = heuristic_parse("search Alex Marsh from AI Security Industry")
        self.assertEqual(p["subject"].lower(), "alex marsh")
        self.assertIn("ai security", p["context"].lower())

    def test_no_context_is_empty_not_garbage(self):
        from blacknoir.intent import heuristic_parse
        p = heuristic_parse("search Jensen Huang")
        self.assertEqual(p["context"], "")

    def test_context_reaches_every_query(self):
        from blacknoir.agent import Agent
        inv = Investigation(target="Alex Marsh", target_type="person",
                            surfaces=["public"], started="now",
                            context="AI security industry")
        qs = Agent._build_queries(inv, deep=False)
        self.assertTrue(all("ai security industry" in q.lower() for q in qs[:1]))
        self.assertGreaterEqual(
            sum("ai security industry" in q.lower() for q in qs), len(qs) - 1)

    def test_built_queries_carry_no_rejected_operators(self):
        from blacknoir.agent import Agent
        from blacknoir.config import has_advanced_operators
        inv = Investigation(target="Alex Marsh", target_type="person",
                            surfaces=["public"], started="now",
                            context="AI security")
        for q in Agent._build_queries(inv, deep=True):
            self.assertFalse(has_advanced_operators(q),
                             f"query would be rejected by free-tier SERP: {q!r}")


class TestPlaceholderSubject(unittest.TestCase):
    """An image description is not a searchable identifier."""

    def test_model_placeholders_are_caught(self):
        from blacknoir.pipeline import _is_placeholder_subject
        for s in ("unknown subject (image)", "unknown person", "Unknown Person",
                  "unidentified individual", "an unknown man", "the person",
                  "selfie", "image", "photo", "anonymous subject", ""):
            self.assertTrue(_is_placeholder_subject(s), s)

    def test_real_identifiers_are_not_caught(self):
        from blacknoir.pipeline import _is_placeholder_subject
        for s in ("Alex Marsh", "A. Rivera", "acme-corp.com", "@nightowl",
                  "nova_reyes_art", "Personal Data Ltd", "Imageworks Studio"):
            self.assertFalse(_is_placeholder_subject(s), s)

    def test_person_nouns_and_filenames_are_caught(self):
        """Regression: 'person in photo.jpg' was searched as if it were a name."""
        from blacknoir.pipeline import _is_placeholder_subject
        for s in ("person in photo.jpg", "the boy in the photo", "girl in picture",
                  "kid in me.png", "photo.jpg", "guy in the selfie",
                  "teenager in image", "child in photo.jpeg",
                  "young man in the portrait", "student in me.webp"):
            self.assertTrue(_is_placeholder_subject(s), s)

    def test_filename_anywhere_is_a_placeholder(self):
        from blacknoir.pipeline import _is_placeholder_subject
        self.assertTrue(_is_placeholder_subject("Alex Marsh in photo.jpg"))


class TestCandidateGrading(unittest.TestCase):
    """A candidate that matches the context 0.00 is never 'confirmed'."""

    def _cand(self, score, n_evidence, name="Alex Marsh"):
        from blacknoir.deepsearch import Candidate
        c = Candidate(label="x", context_match=score)
        # evidence that actually NAMES the person — the confirm path requires it
        c.evidence = [SearchResult("s", "public", f"{name} result {i}")
                      for i in range(n_evidence)]
        return c

    def _state(self, context, target="Alex Marsh"):
        from blacknoir.deepsearch import DeepSearchState
        return DeepSearchState(target=target, context=context)

    def test_zero_match_with_context_is_never_confirmed(self):
        from blacknoir.deepsearch import _grade
        c = self._cand(0.0, 5)
        self.assertEqual(_grade(c, self._state("AI security"), 2), "weak")

    def test_good_match_with_evidence_confirms(self):
        from blacknoir.deepsearch import _grade
        c = self._cand(0.9, 5)
        self.assertEqual(_grade(c, self._state("AI security"), 2), "confirmed")

    def test_no_evidence_is_dry(self):
        from blacknoir.deepsearch import _grade
        self.assertEqual(_grade(self._cand(0.9, 0), self._state("x"), 2), "dry")

    def test_without_context_evidence_alone_decides(self):
        from blacknoir.deepsearch import _grade
        c = self._cand(0.0, 5)
        self.assertEqual(_grade(c, self._state(""), 2), "confirmed")

    def test_context_matches_but_person_unnamed_is_weak(self):
        # Fix A: evidence pages match the context (school) at 1.00 yet never name
        # the person -> must NOT be 'confirmed', only 'weak'.
        from blacknoir.deepsearch import Candidate, _grade, DeepSearchState
        c = Candidate(label="x", context_match=1.0)
        c.evidence = [SearchResult("s", "public", "Ko Lui Secondary School",
                                   snippet="a secondary school in Kwun Tong")
                      for _ in range(5)]
        st = DeepSearchState(target="Wong Jing Yi",
                             context="Ko Lui Secondary School")
        self.assertEqual(_grade(c, st, 2), "weak")


class TestQuestionsNeverEchoTheAsk(unittest.TestCase):
    """Regression: it asked 'Who is the person in the self-portrait?'"""

    def test_echo_questions_are_stripped(self):
        from blacknoir.deepsearch import _ECHO_QUESTION
        for q in ("Who is the person depicted in the self-portrait?",
                  "Who is this?", "What is the name of the subject?",
                  "Can you name the individual?", "Identify the person shown."):
            self.assertTrue(_ECHO_QUESTION.search(q), q)

    def test_useful_questions_survive(self):
        from blacknoir.deepsearch import _ECHO_QUESTION
        for q in ("What does 'SBC' stand for?",
                  "Which city was this taken in?",
                  "Do you know their employer or school?",
                  "What username do they use?"):
            self.assertIsNone(_ECHO_QUESTION.search(q), q)


class TestMemoryRejectsPlaceholders(unittest.TestCase):
    def test_placeholder_target_is_not_remembered(self):
        from blacknoir import memory as m
        d = tempfile.mkdtemp()
        state = {"candidates": [{"label": "x", "outcome": "confirmed",
                                 "context_match": 0.0, "attributes": {},
                                 "evidence": [{"title": "t", "url": "u"}]}]}
        self.assertFalse(m.remember("person in photo.jpg", "", state, memory_dir=d))
        self.assertIsNone(m.recall("person in photo.jpg", memory_dir=d))


class TestClarifyingQuestions(unittest.TestCase):
    """Ask when ambiguous instead of confidently picking the wrong person."""

    def _st(self, context):
        from blacknoir.deepsearch import DeepSearchState
        return DeepSearchState(target="Kai Novak", context=context)

    def _c(self, label, score):
        from blacknoir.deepsearch import Candidate
        return Candidate(label=label, context_match=score)

    def test_unexpanded_acronym_is_flagged(self):
        from blacknoir.deepsearch import ambiguity_reasons
        st = self._st("SBC")
        reasons = ambiguity_reasons(st, [self._c("someone", 0.9)])
        self.assertTrue(any("SBC" in r for r in reasons), reasons)

    def test_common_acronyms_are_not_flagged(self):
        from blacknoir.deepsearch import ambiguity_reasons
        st = self._st("AI security")
        reasons = ambiguity_reasons(st, [self._c("someone", 0.9)])
        self.assertFalse(any("abbreviation" in r for r in reasons), reasons)

    def test_close_scores_are_flagged(self):
        from blacknoir.deepsearch import ambiguity_reasons
        st = self._st("shipping")
        reasons = ambiguity_reasons(
            st, [self._c("a", 0.62), self._c("b", 0.60)])
        self.assertTrue(any("cannot be told apart" in r for r in reasons))

    def test_confident_result_asks_nothing(self):
        from blacknoir.deepsearch import ambiguity_reasons
        st = self._st("shipping")
        self.assertEqual(
            ambiguity_reasons(st, [self._c("a", 0.95), self._c("b", 0.1)]), [])

    def test_questions_generated_without_an_llm(self):
        """The acronym question must work with no model available."""
        from blacknoir.deepsearch import clarifying_questions
        st = self._st("SBC")
        qs = clarifying_questions(st, [self._c("a", 0.5), self._c("b", 0.45)],
                                  agent=None)
        self.assertTrue(qs)
        self.assertTrue(any("SBC" in q for q in qs), qs)

    def test_no_questions_when_unambiguous(self):
        from blacknoir.deepsearch import clarifying_questions
        st = self._st("quantum computing")
        self.assertEqual(
            clarifying_questions(st, [self._c("a", 0.95)], agent=None), [])


class TestConfidenceCap(unittest.TestCase):
    """An unresolved identity cannot be reported as high confidence."""

    def test_open_questions_cap_confidence(self):
        inv = Investigation(target="Kai Novak", target_type="person",
                            surfaces=["public"], started="now", context="SBC")
        inv.deep_search = {"questions": ["What does SBC stand for?"]}
        inv.synthesis = {"confidence": "high", "summary": "found them"}
        open_qs = inv.deep_search.get("questions") or []
        if open_qs and inv.synthesis.get("confidence") == "high":
            inv.synthesis["confidence"] = "medium"
            inv.synthesis.setdefault("risk_notes", []).insert(
                0, f"Confidence capped: {len(open_qs)} question(s) about the "
                   f"target's identity remain unanswered.")
        self.assertEqual(inv.synthesis["confidence"], "medium")
        self.assertIn("Confidence capped", inv.synthesis["risk_notes"][0])


class TestNameVariants(unittest.TestCase):
    """Records are often filed under another rendering of the same name."""

    def test_surname_first_and_initialled_forms(self):
        from blacknoir.deepsearch import _name_variants
        v = [x.lower() for x in _name_variants("Kai Novak")]
        self.assertIn("novak kai", v)
        self.assertTrue(any(x.startswith("k.") for x in v), v)

    def test_middle_name_dropped(self):
        from blacknoir.deepsearch import _name_variants
        self.assertIn("Maria Rodriguez",
                      _name_variants("Maria Elena Rodriguez"))

    def test_single_token_has_no_variants(self):
        from blacknoir.deepsearch import _name_variants
        self.assertEqual(_name_variants("nightowl"), [])

    def test_original_is_never_returned(self):
        from blacknoir.deepsearch import _name_variants
        self.assertNotIn("kai novak",
                         [x.lower() for x in _name_variants("Kai Novak")])


class TestRefine(unittest.TestCase):
    """Follow-up detail narrows an existing investigation without re-running it."""

    def _prev(self):
        return {"mode": "llm", "candidates": [
            {"label": "A. Rivera (Rotterdam shipping)", "role": "Analyst",
             "org": "Blue Harbour", "location": "Rotterdam",
             "context_match": 0.6, "outcome": "confirmed", "rounds": 1,
             "attributes": {}, "queries_run": ["A. Rivera shipping"],
             "evidence": [{"title": "Rivera at Blue Harbour",
                           "url": "https://example.com/1", "snippet": "Rotterdam"}]},
            {"label": "A. Rivera (Sydney teacher)", "role": "Teacher",
             "org": "Sydney High", "location": "Sydney",
             "context_match": 0.5, "outcome": "confirmed", "rounds": 1,
             "attributes": {}, "queries_run": [],
             "evidence": [{"title": "Rivera teaches in Sydney",
                           "url": "https://example.com/2", "snippet": "Sydney"}]},
        ]}

    def test_candidate_roundtrips_from_state(self):
        from blacknoir.deepsearch import _candidate_from_dict
        c = _candidate_from_dict(self._prev()["candidates"][0])
        self.assertEqual(c.org, "Blue Harbour")
        self.assertEqual(len(c.evidence), 1)
        self.assertEqual(c.evidence[0].url, "https://example.com/1")

    def test_heuristic_rescore_boosts_matching_candidate(self):
        """With no LLM, the detail still re-ranks by keyword overlap."""
        from blacknoir.deepsearch import (rescore_with_detail, DeepSearchState,
                                          _candidate_from_dict)
        st = DeepSearchState(target="A. Rivera", context="shipping")
        cands = [_candidate_from_dict(d) for d in self._prev()["candidates"]]
        out = rescore_with_detail(st, cands, "the one in Rotterdam", None)
        self.assertEqual(out[0].location, "Rotterdam")
        self.assertGreater(out[0].context_match, out[1].context_match)

    def test_refine_without_prior_candidates_is_safe(self):
        from blacknoir.deepsearch import refine
        st, runs = refine({}, "extra detail", "A. Rivera", "shipping",
                          "person", ["public"], None, None)
        self.assertEqual(st.candidates, [])
        self.assertTrue(any("run a search first" in n for n in st.notes))

    def test_refine_merges_context(self):
        from blacknoir.deepsearch import refine
        st, _ = refine({}, "teenager", "A. Rivera", "shipping",
                       "person", ["public"], None, None)
        self.assertIn("shipping", st.context)
        self.assertIn("teenager", st.context)


class TestVisionLeads(unittest.TestCase):
    """Vision returns ranked, evidence-backed leads — never face-based ID."""

    def test_leads_parsed_and_ranked(self):
        from blacknoir.agent import Agent
        out = json.dumps({
            "subject_type": "artwork", "description": "abstract art",
            "transcription": "sig: @nova_reyes_art",
            "names": [], "usernames": [], "handles": ["@nova_reyes_art"],
            "domains": ["novareyes-studio.example"], "emails": [],
            "watermarks": [], "platforms": [], "identifiability": "marks",
            "leads": [
                {"hypothesis": "weak lead", "basis": "style only",
                 "confidence": 0.2, "how_to_verify": "x"},
                {"hypothesis": "handle owns this work", "basis": "signature",
                 "confidence": 0.85, "how_to_verify": "check the profile"},
            ]})
        res = Agent._parse_vision(out)
        self.assertEqual(len(res["leads"]), 2)
        self.assertEqual(res["leads"][0]["confidence"], 0.85)   # ranked
        self.assertIn("0.85", res["analysis"])

    def test_lead_without_basis_is_dropped(self):
        """An unsupported hypothesis is a guess with a score attached."""
        from blacknoir.agent import Agent
        out = json.dumps({"subject_type": "person", "leads": [
            {"hypothesis": "this is a famous person", "basis": "",
             "confidence": 0.9}]})
        self.assertEqual(Agent._parse_vision(out)["leads"], [])

    def test_face_only_states_the_limit(self):
        from blacknoir.agent import Agent
        out = json.dumps({"subject_type": "person", "description": "a portrait",
                          "identifiability": "face-only", "leads": []})
        res = Agent._parse_vision(out)
        self.assertEqual(res["leads"], [])
        self.assertIn("does not attribute identity from facial",
                      res["analysis"])

    def test_confidence_is_clamped(self):
        from blacknoir.agent import Agent
        out = json.dumps({"leads": [
            {"hypothesis": "h", "basis": "b", "confidence": 9.9},
            {"hypothesis": "h2", "basis": "b2", "confidence": "bad"}]})
        confs = [L["confidence"] for L in Agent._parse_vision(out)["leads"]]
        self.assertTrue(all(0.0 <= c <= 1.0 for c in confs), confs)


class TestOffTargetFiltering(unittest.TestCase):
    """Onion/Telegram keyword noise must not appear as findings."""

    def _run(self, *results):
        return SourceRun("lyzem", "Lyzem", "darkweb", "ok",
                         results=list(results))

    def test_unrelated_darkweb_results_hidden(self):
        from blacknoir.pipeline import _filter_offtarget
        run = self._run(
            SearchResult("lyzem", "darkweb", "A. Rivera shipping records",
                         url="https://t.me/x", snippet="A. Rivera manifest"),
            SearchResult("lyzem", "darkweb", "Amfetamin kupit zakladku",
                         url="https://telegra.ph/y", snippet="drug advert"),
            SearchResult("lyzem", "darkweb", "LyzemBot",
                         url="https://t.me/lyzembot", snippet="engine bot"),
        )
        out = _filter_offtarget(run, "A. Rivera", "shipping")
        self.assertEqual(len(out.results), 1)
        self.assertIn("Rivera", out.results[0].title)
        self.assertIn("2 result(s) hidden", out.detail)

    def test_status_downgrades_when_everything_was_noise(self):
        from blacknoir.pipeline import _filter_offtarget
        run = self._run(SearchResult("lyzem", "darkweb", "unrelated channel",
                                     url="https://t.me/z", snippet="ads"))
        out = _filter_offtarget(run, "A. Rivera", "shipping")
        self.assertEqual(out.results, [])
        self.assertEqual(out.status, "empty")

    def test_on_target_results_survive_untouched(self):
        from blacknoir.pipeline import _filter_offtarget
        run = self._run(SearchResult("lyzem", "darkweb", "A. Rivera leak",
                                     url="https://t.me/a", snippet="Rivera"))
        out = _filter_offtarget(run, "A. Rivera", "")
        self.assertEqual(len(out.results), 1)
        self.assertEqual(out.status, "ok")


class TestLLMErrorSurfacing(unittest.TestCase):
    """A failed model call must report why, not fall silent."""

    def test_vision_failure_names_the_cause(self):
        from blacknoir.llm import LLM

        class Boom:
            def vision(self, *a):
                raise RuntimeError("image too large")

        llm = LLM.__new__(LLM)
        llm.backend, llm.vision_ok = Boom(), True
        llm._errors, llm._idx, llm._chain = 0, 0, ["google"]
        llm.error_threshold, llm.last_error, llm._log = 2, None, None
        out = llm.complete_vision("s", "p", "b64", "image/png", 100)
        self.assertIn("vision call failed", out)
        self.assertIn("image too large", out)


class TestMemory(unittest.TestCase):
    """Investigation memory: recall, warm start, and real erasure."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def _state(self, outcome="confirmed"):
        return {"candidates": [{
            "label": "A. Rivera (shipping analyst)", "role": "Analyst",
            "org": "Blue Harbour Lines", "location": "Rotterdam",
            "context_match": 0.9, "outcome": outcome, "rounds": 2,
            "attributes": {"usernames": ["arivera"], "orgs": ["Blue Harbour Lines"]},
            "evidence": [{"title": "profile", "url": "https://example.com/a"}],
        }]}

    def test_remember_then_recall(self):
        from blacknoir import memory as m
        self.assertTrue(m.remember("A. Rivera", "shipping", self._state(),
                                   memory_dir=self.dir))
        got = m.recall("A. Rivera", "shipping", memory_dir=self.dir)
        self.assertIsNotNone(got)
        self.assertEqual(got["identities"][0]["org"], "Blue Harbour Lines")

    def test_recall_matches_when_context_phrasing_differs(self):
        from blacknoir import memory as m
        m.remember("A. Rivera", "shipping industry", self._state(),
                   memory_dir=self.dir)
        self.assertIsNotNone(m.recall("A. Rivera", "maritime freight",
                                      memory_dir=self.dir))

    def test_rejected_namesakes_are_not_stored(self):
        from blacknoir import memory as m
        self.assertFalse(m.remember("A. Rivera", "shipping",
                                    self._state(outcome="skipped"),
                                    memory_dir=self.dir))
        self.assertIsNone(m.recall("A. Rivera", "shipping", memory_dir=self.dir))

    def test_prior_terms_seed_recon_queries(self):
        from blacknoir import memory as m
        from blacknoir.deepsearch import _recon_queries
        m.remember("A. Rivera", "shipping", self._state(), memory_dir=self.dir)
        terms = m.prior_terms(m.recall("A. Rivera", "shipping",
                                       memory_dir=self.dir))
        self.assertIn("Blue Harbour Lines", terms)
        qs = _recon_queries("A. Rivera", "shipping", "person", terms)
        self.assertIn("blue harbour lines", " ".join(qs).lower())

    def test_memory_off_records_nothing(self):
        from blacknoir import memory as m
        self.assertFalse(m.remember("A. Rivera", "shipping", self._state(),
                                    memory_dir=self.dir, flag="off"))
        self.assertIsNone(m.recall("A. Rivera", "shipping",
                                   memory_dir=self.dir, flag="off"))

    def test_forget_really_deletes(self):
        from blacknoir import memory as m
        m.remember("A. Rivera", "shipping", self._state(), memory_dir=self.dir)
        self.assertEqual(m.forget("A. Rivera", memory_dir=self.dir), 1)
        self.assertIsNone(m.recall("A. Rivera", "shipping", memory_dir=self.dir))
        # gone from the file itself, not tombstoned
        raw = Path(self.dir, "investigations.json").read_text(encoding="utf-8")
        self.assertNotIn("Rivera", raw)
        self.assertNotIn("Blue Harbour", raw)

    def test_forget_works_even_when_memory_disabled(self):
        """Turning recording off must not trap already-stored data."""
        from blacknoir import memory as m
        m.remember("A. Rivera", "shipping", self._state(), memory_dir=self.dir)
        os.environ["BLACKNOIR_MEMORY"] = "off"
        try:
            self.assertEqual(m.forget("A. Rivera", memory_dir=self.dir), 1)
        finally:
            os.environ.pop("BLACKNOIR_MEMORY", None)

    def test_forget_all_removes_the_file(self):
        from blacknoir import memory as m
        m.remember("A. Rivera", "shipping", self._state(), memory_dir=self.dir)
        m.remember("K. Novak", "games", self._state(), memory_dir=self.dir)
        self.assertEqual(m.forget_all(memory_dir=self.dir), 2)
        self.assertFalse(Path(self.dir, "investigations.json").exists())

    def test_corrupt_store_degrades_to_empty(self):
        """A damaged file must never break an investigation."""
        from blacknoir import memory as m
        Path(self.dir, "investigations.json").write_text("{not json",
                                                         encoding="utf-8")
        self.assertIsNone(m.recall("anyone", memory_dir=self.dir))
        self.assertEqual(m.entries(memory_dir=self.dir), [])

    def test_store_is_listable_in_full(self):
        from blacknoir import memory as m
        m.remember("A. Rivera", "shipping", self._state(), memory_dir=self.dir)
        text = m.describe_store(memory_dir=self.dir)
        self.assertIn("A. Rivera", text)
        self.assertIn("Blue Harbour Lines", text)
        self.assertIn("https://example.com/a", text)
        self.assertIn("--forget", text)


class TestGeneralization(unittest.TestCase):
    """Guards against tuning the parser to one target.

    Every case here uses a name/phrasing unrelated to any target used while
    developing these features.
    """

    def _p(self, raw):
        from blacknoir.intent import heuristic_parse
        return heuristic_parse(raw)

    def test_varied_qualifier_phrasings(self):
        cases = [
            ("search Maria Rodriguez working at NASA", "Maria Rodriguez", "nasa"),
            ("find Kenji Tanaka from Sony Interactive", "Kenji Tanaka", "sony"),
            ('"Aisha Bello" based in Lagos fintech', "Aisha Bello", "lagos"),
            ("look up Dr. Elena Petrova at CERN", "Petrova", "cern"),
            ("who is Liam O'Connor of Trinity College Dublin",
             "O'Connor", "trinity"),
            ("investigate Priya Sharma employed by Infosys",
             "Priya Sharma", "infosys"),
        ]
        for raw, subj, ctx in cases:
            p = self._p(raw)
            self.assertIn(subj.lower(), p["subject"].lower(), raw)
            self.assertIn(ctx, p["context"].lower(), raw)

    def test_no_qualifier_yields_empty_context(self):
        for raw in ("search John Smith", "deep dive on acme-corp.com",
                    "find @nightowl_23"):
            self.assertEqual(self._p(raw)["context"], "", raw)

    def test_org_names_containing_connectives_survive(self):
        """'Bank of America' must not become subject 'Bank', context 'America'."""
        for raw in ("University of California", "Bank of America",
                    "Massachusetts Institute of Technology",
                    "Isle of Man registry"):
            p = self._p(raw)
            self.assertEqual(p["context"], "", raw)
            # the distinguishing word after the connective is retained
            self.assertIn(raw.split()[-1].lower(), p["subject"].lower(), raw)

    def test_proper_nouns_not_stripped_as_pronouns(self):
        """'Man' in 'Isle of Man' is a place, not the pronoun filler."""
        self.assertIn("man", self._p("Isle of Man registry")["subject"].lower())

    def test_relevance_gate_on_unrelated_names(self):
        from blacknoir.entities import is_about_target
        self.assertTrue(is_about_target("Maria Rodriguez - NASA engineer",
                                        "Maria Rodriguez", "NASA"))
        self.assertFalse(is_about_target("Maria Sanchez - NASA engineer",
                                         "Maria Rodriguez", "NASA"))
        self.assertTrue(is_about_target("Tanaka, Kenji - profile",
                                        "Kenji Tanaka", ""))
        self.assertFalse(is_about_target("Wong Tai Man - HKU",
                                         "Chan Siu Ming", "HKU"))

    def test_queries_generalise_across_target_types(self):
        from blacknoir.agent import Agent
        from blacknoir.config import has_advanced_operators
        for target, ttype, ctx in [("Maria Rodriguez", "person", "NASA"),
                                   ("Kenji Tanaka", "person", ""),
                                   ("acme-corp.com", "domain", ""),
                                   ("nightowl_23", "username", "modding"),
                                   ("a@b.com", "email", "")]:
            inv = Investigation(target=target, target_type=ttype,
                                surfaces=["public"], started="now", context=ctx)
            qs = Agent._build_queries(inv, deep=True)
            self.assertTrue(qs, target)
            for q in qs:
                self.assertFalse(has_advanced_operators(q), f"{target}: {q!r}")
            if ctx:
                self.assertIn(ctx.lower(), qs[0].lower(), target)


class TestQuerySanitizer(unittest.TestCase):
    """Free Serper answers HTTP 400 to quotes and operators."""

    def test_strips_quotes_keeping_words(self):
        from blacknoir.config import sanitize_query
        self.assertEqual(sanitize_query('"Alex Marsh" LinkedIn'),
                         "Alex Marsh LinkedIn")

    def test_strips_site_and_boolean_operators(self):
        from blacknoir.config import sanitize_query
        self.assertEqual(sanitize_query("Alex Marsh site:linkedin.com"),
                         "Alex Marsh")
        self.assertEqual(sanitize_query("Alex Marsh company OR employer"),
                         "Alex Marsh company employer")

    def test_detects_advanced_operators(self):
        from blacknoir.config import has_advanced_operators
        self.assertTrue(has_advanced_operators('"Alex Marsh"'))
        self.assertTrue(has_advanced_operators("x site:y.com"))
        self.assertFalse(has_advanced_operators("Alex Marsh AI security"))

    def test_plain_query_is_unchanged(self):
        from blacknoir.config import sanitize_query
        self.assertEqual(sanitize_query("Alex Marsh AI security"),
                         "Alex Marsh AI security")


class TestRelevanceGate(unittest.TestCase):
    """Off-target results must not invent edges in the entity graph."""

    def test_namesake_noise_is_rejected(self):
        from blacknoir.entities import is_about_target
        self.assertFalse(is_about_target(
            "Home | Marsh's Deli marshdeli.example", "Alex Marsh", "AI security"))
        self.assertFalse(is_about_target(
            "Alex Stone - IMDb", "Alex Marsh", "AI security"))

    def test_full_name_match_accepted(self):
        from blacknoir.entities import is_about_target
        self.assertTrue(is_about_target(
            "AMarsh-Sec (Alex Marsh) GitHub", "Alex Marsh", "AI security"))

    def test_partial_match_requires_surname_plus_context(self):
        from blacknoir.entities import is_about_target
        # surname present + context agrees -> plausible
        self.assertTrue(is_about_target(
            "Marsh presenting AI security research", "Alex Marsh", "AI security"))
        # surname missing -> rejected even when context agrees
        self.assertFalse(is_about_target(
            "Alex Vance - Wikipedia", "Alex Marsh", "AI security"))

    def test_shared_first_name_is_not_a_match(self):
        """A common first name plus matching context must not qualify.

        Regression: 'Alex Bell' and 'Alex Doyle' both entered the graph
        for a 'Alex Marsh' search because they share 'Alex' and appear in
        AI-security articles.
        """
        from blacknoir.entities import is_about_target
        for other in ("Ep. 156: AI Security & Threat Modeling w/ Alex Bell",
                      "Alex Doyle, Deputy CISO of Anthropic, warns about AI"):
            self.assertFalse(is_about_target(other, "Alex Marsh", "AI security"),
                             f"namesake leaked into graph: {other!r}")

    def test_correlate_drops_offtarget_results(self):
        inv = Investigation(target="Alex Marsh", target_type="person",
                            surfaces=["public"], started="now",
                            context="AI security")
        inv.runs = [SourceRun("serper", "Serper", "public", "ok", results=[
            SearchResult("serper", "public", "Alex Marsh AI security",
                         url="https://alexmarsh.dev",
                         snippet="Alex Marsh - Independent AI researcher"),
            SearchResult("serper", "public", "Home | Marsh's Deli",
                         url="https://marshdeli.example",
                         snippet="Fresh ingredients, great value"),
        ])]
        correlate(inv)
        values = {e.value.lower() for e in inv.entities}
        # on-target result contributes its (non-platform) domain
        self.assertIn("alexmarsh.dev", values)
        # off-target result contributes nothing
        self.assertNotIn("marshdeli.example", values)
        self.assertEqual(inv.correlation_skipped, 1)

    def test_wayback_timestamp_is_not_a_phone_number(self):
        inv = Investigation(target="Alex Marsh", target_type="person",
                            surfaces=["public"], started="now")
        inv.runs = [SourceRun("enrich_domain", "Domain recon", "public", "ok",
                              results=[SearchResult(
                                  "enrich_domain", "public",
                                  "Wayback snapshot 20260817234951",
                                  url="http://web.archive.org/web/20260817234951/")])]
        correlate(inv)
        phones = [e.value for e in inv.entities if e.kind == "phone"]
        self.assertEqual(phones, [])


class _FakeSerperFetcher:
    """Records queries; optionally refuses operator syntax like a free plan."""

    def __init__(self, refuse_operators: bool):
        self.refuse = refuse_operators
        self.sent = []
        self.last_error = None
        self.last_status = None
        self.live = True

    def post(self, url, json_body=None, headers=None, as_json=False, **kw):
        q = (json_body or {}).get("q", "")
        self.sent.append(q)
        from blacknoir.config import has_advanced_operators
        if self.refuse and has_advanced_operators(q):
            self.last_error = (400,
                               "Query pattern not allowed for free accounts.")
            return None
        self.last_error = None
        return {"organic": [{"title": "hit", "link": "https://example.com/x",
                             "snippet": "s"}]}


class TestSerperOperatorFallback(unittest.TestCase):
    """Operators are preserved when the plan allows them, dropped when not."""

    def setUp(self):
        os.environ["SERPER_API_KEY"] = "test-key"

    def _run(self, query, refuse):
        from blacknoir.connectors import _run_serper
        f = _FakeSerperFetcher(refuse)
        run = _run_serper(REGISTRY["serper"], query, f)
        return run, f.sent

    def test_operators_preserved_when_plan_allows(self):
        run, sent = self._run('"Alex Marsh" LinkedIn', refuse=False)
        self.assertEqual(run.status, "ok")
        # asked exactly once, with the precise query intact
        self.assertEqual(sent, ['"Alex Marsh" LinkedIn'])

    def test_falls_back_to_plain_when_plan_refuses(self):
        run, sent = self._run('"Alex Marsh" LinkedIn', refuse=True)
        self.assertEqual(run.status, "ok")
        self.assertEqual(len(sent), 2)
        self.assertEqual(sent[0], '"Alex Marsh" LinkedIn')   # precise first
        self.assertEqual(sent[1], "Alex Marsh LinkedIn")     # fallback second
        self.assertIn("plain keywords", run.detail)

    def test_plain_query_never_retried(self):
        run, sent = self._run("Alex Marsh AI security", refuse=True)
        self.assertEqual(run.status, "ok")
        self.assertEqual(sent, ["Alex Marsh AI security"])

    def test_real_error_is_reported_not_guessed(self):
        """A failure must name the actual cause, not assume a rate limit."""
        from blacknoir.connectors import _run_serper

        class Dead(_FakeSerperFetcher):
            def post(self, *a, **k):
                self.last_error = (402, "Insufficient credits")
                return None

        run = _run_serper(REGISTRY["serper"], "Alex Marsh", Dead(False))
        self.assertEqual(run.status, "blocked")
        self.assertIn("402", run.detail)
        self.assertIn("Insufficient credits", run.detail)
        self.assertNotIn("rate-limited", run.detail)


class TestDeepSearchLoop(unittest.TestCase):
    """The iterative candidate loop: clustering, budgets and termination."""

    def _state(self, context="AI security"):
        from blacknoir.deepsearch import DeepSearchState
        return DeepSearchState(target="Alex Marsh", context=context)

    def _cand(self, label, score):
        from blacknoir.deepsearch import Candidate
        return Candidate(label=label, context_match=score)

    def test_namesakes_below_floor_are_not_profiled(self):
        from blacknoir.deepsearch import _select_candidates, MIN_CONTEXT_MATCH
        st = self._state()
        st.candidates = [self._cand("AI researcher", 1.0),
                         self._cand("real estate", 0.0),
                         self._cand("manufacturing", 0.0)]
        picked = _select_candidates(st)
        self.assertEqual([c.label for c in picked], ["AI researcher"])
        self.assertTrue(all(c.context_match >= MIN_CONTEXT_MATCH
                            for c in picked))

    def test_best_candidate_kept_even_if_all_score_low(self):
        from blacknoir.deepsearch import _select_candidates
        st = self._state()
        st.candidates = [self._cand("weak a", 0.1), self._cand("weak b", 0.0)]
        picked = _select_candidates(st)
        self.assertEqual(len(picked), 1)
        self.assertEqual(picked[0].label, "weak a")

    def test_without_context_floor_does_not_apply(self):
        from blacknoir.deepsearch import _select_candidates, MAX_CANDIDATES
        st = self._state(context="")
        st.candidates = [self._cand(f"c{i}", 0.0) for i in range(5)]
        picked = _select_candidates(st)
        self.assertEqual(len(picked), min(5, MAX_CANDIDATES))

    def test_query_budget_is_a_hard_ceiling(self):
        """A blocked engine must not let the loop spin forever."""
        from blacknoir import deepsearch
        from blacknoir.config import REGISTRY
        st = self._state()
        st.queries_spent = deepsearch.QUERY_BUDGET
        calls = []

        def boom(*a, **k):
            calls.append(1)
            raise AssertionError("must not query past the budget")

        orig = deepsearch.run_source
        deepsearch.run_source = boom
        try:
            fresh = deepsearch._run_queries(
                [REGISTRY["serper"]], ["a", "b", "c"], None, st, set())
        finally:
            deepsearch.run_source = orig
        self.assertEqual(fresh, [])
        self.assertEqual(calls, [])
        self.assertTrue(any("budget" in n for n in st.notes))

    def test_anchor_terms_drive_deeper_queries(self):
        from blacknoir.deepsearch import _round_queries_heuristic
        st = self._state()
        c = self._cand("x", 1.0)
        c.org, c.role = "Northwind AI", "security researcher"
        c.attributes = {"handles": ["AMarsh-Sec"]}
        qs = _round_queries_heuristic(st, c, depth=2)
        joined = " ".join(qs).lower()
        self.assertIn("northwind ai", joined)
        self.assertIn("amarsh-sec", joined)

    def test_heuristic_clustering_splits_by_profile_anchor(self):
        from blacknoir.deepsearch import cluster_heuristic
        st = self._state()
        results = [
            SearchResult("serper", "public", "Alex Marsh AI security",
                         url="https://hk.linkedin.com/in/alex-marsh-0100",
                         snippet="Alex Marsh independent AI security researcher"),
            SearchResult("serper", "public", "Alex Marsh profile",
                         url="https://www.linkedin.com/in/amarsh87",
                         snippet="Alex Marsh director of software"),
        ]
        cands = cluster_heuristic(st, results)
        anchors = {a for c in cands for a in c.attributes.get("usernames", [])}
        self.assertIn("alex-marsh-0100", anchors)
        self.assertIn("amarsh87", anchors)

    def test_clustering_drops_offtarget_noise(self):
        from blacknoir.deepsearch import cluster_heuristic
        st = self._state()
        results = [SearchResult("serper", "public", "Alex Stone - IMDb",
                                url="https://www.imdb.com/name/nm0000",
                                snippet="English actor")]
        self.assertEqual(cluster_heuristic(st, results), [])

    def test_sanitized_queries_only(self):
        """Every query the loop emits must survive a free-tier SERP API."""
        from blacknoir.deepsearch import _recon_queries, _round_queries_heuristic
        from blacknoir.config import has_advanced_operators
        st = self._state()
        c = self._cand("x", 1.0)
        c.org = "Northwind AI"
        qs = (_recon_queries("Alex Marsh", "AI security", "person")
              + _round_queries_heuristic(st, c, depth=1)
              + _round_queries_heuristic(st, c, depth=3))
        for q in qs:
            self.assertFalse(has_advanced_operators(q), f"rejected query: {q!r}")


class TestSourceAvailability(unittest.TestCase):
    """Sources with no way to run must not be reported as queried."""

    def setUp(self):
        self._saved = {k: os.environ.get(k) for k in
                       ("TORCH_CMD", "DARKWEB_SCRAPER_CMD", "TELEPATHY_CMD",
                        "VPN_UP_CMD", "INTELX_API_KEY", "GITHUB_TOKEN")}

    def tearDown(self):
        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def test_command_only_source_unavailable_without_command(self):
        os.environ.pop("TORCH_CMD", None)
        s = REGISTRY["torch"]
        self.assertFalse(s.available)
        self.assertIn("TORCH_CMD", s.unavailable_reason)

    def test_command_only_source_available_with_command(self):
        os.environ["TORCH_CMD"] = "torch-cli {q}"
        self.assertTrue(REGISTRY["torch"].available)
        self.assertEqual(REGISTRY["torch"].unavailable_reason, "")

    def test_identity_egress_sources_require_isolation(self):
        # Sources that log in / fetch from this host must be gated on VPN+Docker.
        for k in ("telepathy", "torch", "darkweb_scraper"):
            self.assertTrue(REGISTRY[k].requires_isolation,
                            f"{k} should require isolation")
        # Clearnet, no-account sources must not be gated (they'd break for no
        # reason).
        for k in ("ahmia", "hibp", "duckduckgo", "lyzem"):
            self.assertFalse(REGISTRY[k].requires_isolation,
                             f"{k} must not require isolation")

    def test_connect_vpn_refuses_without_cmd_and_no_tunnel(self):
        # No tunnel up and no VPN_UP_CMD configured -> cannot auto-connect.
        from blacknoir import preflight
        os.environ.pop("VPN_UP_CMD", None)
        saved = preflight.vpn_active
        preflight.vpn_active = lambda: (False, "")
        try:
            self.assertFalse(
                preflight.connect_vpn(lambda m: None, assume_yes=True))
        finally:
            preflight.vpn_active = saved

    def test_connect_vpn_short_circuits_when_tunnel_present(self):
        # An already-active tunnel needs no command and returns True.
        from blacknoir import preflight
        saved = preflight.vpn_active
        preflight.vpn_active = lambda: (True, "wireguard")
        try:
            self.assertTrue(
                preflight.connect_vpn(lambda m: None, assume_yes=False))
        finally:
            preflight.vpn_active = saved

    def test_intelx_key_gated_and_not_identity_egress(self):
        # IntelX is a clearnet API with a key — safe, no VPN/Docker needed.
        s = REGISTRY["intelx"]
        self.assertEqual(s.needs_key, "INTELX_API_KEY")
        self.assertFalse(s.requires_isolation)
        os.environ.pop("INTELX_API_KEY", None)
        self.assertFalse(s.available)
        os.environ["INTELX_API_KEY"] = "x"
        self.assertTrue(s.available)

    def test_intelx_fails_over_to_backup_key(self):
        # Two comma-separated keys: the primary is out of credits (HTTP 402),
        # so the connector must fail over to the backup and still return results.
        from blacknoir.connectors import run_source
        os.environ["INTELX_API_KEY"] = "PRIMARY,BACKUP"

        class FakeFetcher:
            live = True
            last_error = None

            def post(self, url, json_body=None, headers=None, as_json=False):
                if (headers or {}).get("x-key") == "PRIMARY":
                    self.last_error = (402, "payment required")
                    return None
                self.last_error = None
                return {"id": "SID"}

            def get_json(self, url, headers=None, timeout=None):
                if "terminate" in url:
                    return {}
                return {"records": [{"systemid": "s1", "name": "leak.txt",
                                     "bucket": "leaks.public",
                                     "date": "2026-01-01"}], "status": 2}

        run = run_source(REGISTRY["intelx"], "example.com", FakeFetcher())
        self.assertEqual(run.status, "ok")
        self.assertEqual(len(run.results), 1)
        self.assertIn("key #2/2", run.detail)

    def test_intelx_all_keys_exhausted_blocks(self):
        # When every key is out of credits, the source is blocked (not a silent
        # empty that would read as "nothing found").
        from blacknoir.connectors import run_source
        os.environ["INTELX_API_KEY"] = "K1,K2"

        class DeadFetcher:
            live = True
            last_error = (402, "payment required")

            def post(self, *a, **k):
                self.last_error = (402, "payment required")
                return None

            def get_json(self, *a, **k):
                return None

        run = run_source(REGISTRY["intelx"], "example.com", DeadFetcher())
        self.assertEqual(run.status, "blocked")

    def test_keyless_infra_sources_available(self):
        # RDAP/HackerTarget/Mnemonic/Wikidata need no key and are available.
        for k in ("rdap", "reverseip", "hostsearch", "pdns", "wikidata"):
            self.assertIsNone(REGISTRY[k].needs_key)
            self.assertTrue(REGISTRY[k].available)
            self.assertFalse(REGISTRY[k].requires_isolation)

    def test_crtsh_wayback_not_standalone_sources(self):
        # crt.sh/Wayback live in enrich.py, not the registry — no duplicate
        # standalone sources double-querying those services.
        self.assertNotIn("crtsh", REGISTRY)
        self.assertNotIn("wayback", REGISTRY)

    def test_infra_sources_skip_non_domain_target(self):
        # A person-name query is meaningless for RDAP/passive DNS -> skipped,
        # never an error, and never a spurious network call.
        from blacknoir.connectors import run_source
        from blacknoir.http import Fetcher
        f = Fetcher(Guardrails(), live=False)
        for k in ("rdap", "reverseip", "hostsearch", "pdns"):
            self.assertEqual(run_source(REGISTRY[k], "John Smith", f).status,
                             "skipped")

    def test_github_key_gated_and_not_identity_egress(self):
        s = REGISTRY["github"]
        self.assertEqual(s.needs_key, "GITHUB_TOKEN")
        self.assertFalse(s.requires_isolation)
        os.environ.pop("GITHUB_TOKEN", None)
        self.assertFalse(s.available)
        os.environ["GITHUB_TOKEN"] = "x"
        self.assertTrue(s.available)

    def test_psbdmp_not_registered(self):
        # psbdmp is defunct — it must not be a registered source.
        self.assertNotIn("psbdmp", REGISTRY)

    def test_keyless_web_source_always_available(self):
        self.assertTrue(REGISTRY["duckduckgo"].available)


class TestReportCandidates(unittest.TestCase):
    """The report must show identity resolution, not just a link dump."""

    def _inv(self):
        inv = Investigation(target="Alex Marsh", target_type="person",
                            surfaces=["public"], started="now",
                            context="AI security")
        inv.deep_search = {
            "mode": "llm", "queries_spent": 7, "llm_calls": 2,
            "rounds_total": 1, "notes": ["discarded 20 result(s)"],
            "candidates": [
                {"label": "Alex Marsh (AI Security Researcher)", "role": "Apprentice",
                 "org": "Northwind AI", "location": "Hong Kong", "context_match": 1.0,
                 "outcome": "confirmed", "rounds": 1, "why": "strong match",
                 "queries_run": ["Alex Marsh Northwind AI"],
                 "evidence": [{"title": "LinkedIn profile",
                               "url": "https://example.com/in/x"}]},
                {"label": "Alex Marsh (Real Estate)", "role": "Investor",
                 "context_match": 0.0, "outcome": "skipped", "rounds": 0,
                 "queries_run": [], "evidence": []},
            ]}
        return inv

    def test_section_renders_pursued_and_rejected(self):
        from blacknoir.report import _candidates_section
        html = _candidates_section(self._inv())
        self.assertIn("Identity resolution", html)
        self.assertIn("AI Security Researcher", html)
        self.assertIn("match 1.00", html)
        self.assertIn("Northwind AI", html)
        self.assertIn("confirmed", html)
        # the namesake is shown as ruled out, not as a finding
        self.assertIn("Namesakes ruled out", html)
        self.assertIn("Real Estate", html)

    def test_section_absent_when_loop_did_not_run(self):
        from blacknoir.report import _candidates_section
        inv = Investigation(target="northwind.example", target_type="domain",
                            surfaces=["public"], started="now")
        self.assertEqual(_candidates_section(inv), "")

    def test_full_report_renders_with_candidates(self):
        from blacknoir.report import render
        with tempfile.TemporaryDirectory() as d:
            html_path, json_path = render(self._inv(), d)
            html = Path(html_path).read_text(encoding="utf-8")
            self.assertIn("Identity resolution", html)
            self.assertIn("Northwind AI", html)


class TestHeuristicAnchorMerge(unittest.TestCase):
    """One person owning several profiles must be one candidate, not several."""

    def test_cooccurring_anchors_merge_into_one_candidate(self):
        from blacknoir.deepsearch import cluster_heuristic, DeepSearchState
        st = DeepSearchState(target="Alex Marsh", context="AI security")
        results = [
            # a page naming BOTH profiles -> same person
            SearchResult("serper", "public", "Alex Marsh AI security links",
                         url="https://hk.linkedin.com/in/alex-marsh-0100",
                         snippet="Alex Marsh AI security, github.com/AMarsh-Sec"),
            SearchResult("serper", "public", "Alex Marsh AMarsh-Sec",
                         url="https://github.com/AMarsh-Sec",
                         snippet="Alex Marsh AI security research"),
        ]
        cands = cluster_heuristic(st, results)
        self.assertEqual(len(cands), 1, [c.label for c in cands])
        names = {u.lower() for u in cands[0].attributes["usernames"]}
        self.assertIn("alex-marsh-0100", names)
        self.assertIn("amarsh-sec", names)

    def test_unrelated_anchors_stay_separate(self):
        from blacknoir.deepsearch import cluster_heuristic, DeepSearchState
        st = DeepSearchState(target="Alex Marsh", context="AI security")
        results = [
            SearchResult("serper", "public", "Alex Marsh AI security",
                         url="https://hk.linkedin.com/in/alex-marsh-0100",
                         snippet="Alex Marsh AI security researcher"),
            SearchResult("serper", "public", "Alex Marsh software director",
                         url="https://www.linkedin.com/in/amarsh87",
                         snippet="Alex Marsh AI security unrelated director"),
        ]
        self.assertEqual(len(cluster_heuristic(st, results)), 2)


class TestRegistry(unittest.TestCase):
    def test_expected_sources(self):
        for key in ("duckduckgo", "serper", "ahmia", "hibp", "lyzem",
                    "telepathy", "torch", "darkweb_scraper"):
            self.assertIn(key, REGISTRY)

    def test_removed_sources(self):
        # bot-blocked and payment-only sources were removed.
        for key in ("haystak", "onionland", "onionsearch",
                    "telegago", "dehashed"):
            self.assertNotIn(key, REGISTRY)

    def test_bing_restored_with_dedicated_parser(self):
        # Bing was removed 2026-08-26 as "pure noise"; re-measured 2026-08-27
        # the endpoint returns well-formed organic results and the noise came
        # from reading it with the generic anchor scraper. It is only safe to
        # ship while it has a parser of its own.
        from blacknoir.connectors import _PARSERS
        self.assertIn("bing", REGISTRY)
        self.assertIn("bing", _PARSERS)

    def test_surfaces(self):
        self.assertEqual({s.key for s in sources_for_surface("public")},
                         {"duckduckgo", "bing", "serper", "github", "rdap",
                          "reverseip", "hostsearch", "pdns", "wikidata"})
        self.assertTrue(len(sources_for_surface("darkweb")) >= 5)

    def test_serper_source(self):
        s = REGISTRY["serper"]
        self.assertEqual(s.surface, "public")
        self.assertEqual(s.kind, "serp")
        self.assertEqual(s.needs_key, "SERPER_API_KEY")
        self.assertTrue(Guardrails().can_fetch("https://google.serper.dev/search")[0])

    def test_no_onion_bases(self):
        for s in REGISTRY.values():
            self.assertNotIn(".onion", s.clearnet)

    def test_hibp_keyless_available(self):
        # HIBP is keyless for domains, so it must be available without a key.
        self.assertIsNone(REGISTRY["hibp"].needs_key)
        self.assertTrue(REGISTRY["hibp"].available)
        self.assertIn("domain", REGISTRY["hibp"].good_for)

    def test_domainish(self):
        from blacknoir.connectors import _DOMAINISH
        self.assertTrue(_DOMAINISH.match("adobe.com"))
        self.assertTrue(_DOMAINISH.match("sub.example.co.uk"))
        self.assertFalse(_DOMAINISH.match("not a domain"))
        self.assertFalse(_DOMAINISH.match("john@x.com"))


class TestEnv(unittest.TestCase):
    def test_load_dotenv(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / ".env"
            p.write_text("BLACKNOIR_TEST_XYZ=hello\n# comment\nBAD line\n")
            os.environ.pop("BLACKNOIR_TEST_XYZ", None)
            n = load_dotenv(str(p))
            self.assertGreaterEqual(n, 1)
            self.assertEqual(os.environ.get("BLACKNOIR_TEST_XYZ"), "hello")

    def test_no_overwrite(self):
        os.environ["BLACKNOIR_TEST_KEEP"] = "orig"
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / ".env"
            p.write_text("BLACKNOIR_TEST_KEEP=changed\n")
            load_dotenv(str(p))
            self.assertEqual(os.environ["BLACKNOIR_TEST_KEEP"], "orig")


class TestLLM(unittest.TestCase):
    def test_disabled(self):
        llm = LLM(use_llm=False)
        self.assertFalse(llm.enabled)
        self.assertIsNone(llm.complete_text("s", "p"))

    def test_unknown_provider(self):
        llm = LLM(provider="does-not-exist")
        self.assertFalse(llm.enabled)

    def test_specs_present(self):
        for name in ("google", "nvidia", "groq", "cloudflare", "ollama"):
            self.assertIn(name, SPECS)
        # Anthropic/OpenAI removed — never used here.
        self.assertNotIn("anthropic", SPECS)
        self.assertNotIn("openai", SPECS)

    def test_vision_capability(self):
        self.assertTrue(_vision_capable("gpt-4o-mini"))
        self.assertTrue(_vision_capable("gemini-flash-lite-latest"))
        self.assertFalse(_vision_capable("meta/llama-3.1-70b-instruct"))


class TestFailover(unittest.TestCase):
    class _Bad:
        def text(self, *a):
            raise RuntimeError("boom")

    class _Good:
        def text(self, *a):
            return "ok"

    def _wire(self, threshold):
        llm = LLM(use_llm=False)          # start disabled, then wire manually
        llm._chain = ["p1", "p2"]
        llm._idx = 0
        llm.provider, llm.model = "p1", "m1"
        llm.backend = self._Bad()
        llm.error_threshold = threshold
        llm._build_backend = lambda name, use_override: (self._Good(), "m2")
        return llm

    def test_failover_switches_provider(self):
        llm = self._wire(threshold=1)
        out = llm.complete_text("s", "p")
        self.assertEqual(out, "ok")
        self.assertEqual(llm.provider, "p2")   # jumped to the next provider

    def test_unproven_provider_fails_over_on_first_error(self):
        # An UNPROVEN provider gets no tolerance regardless of threshold.
        # Spending the first call of a run discovering the primary is out of
        # quota is what silently dropped whole investigations to heuristics.
        llm = self._wire(threshold=5)
        out = llm.complete_text("s", "p")
        self.assertEqual(out, "ok")
        self.assertEqual(llm.provider, "p2")

    def test_proven_provider_keeps_the_threshold(self):
        # Once a provider has actually answered, a single blip must not cost
        # us a model we know works.
        class _Flaky:
            def __init__(self):
                self.n = 0

            def text(self, *a):
                self.n += 1
                if self.n == 1:
                    return "first"
                raise RuntimeError("blip")

        llm = self._wire(threshold=5)
        llm.backend = _Flaky()
        self.assertEqual(llm.complete_text("s", "p"), "first")   # now proven
        self.assertIsNone(llm.complete_text("s", "p"))           # blip tolerated
        self.assertEqual(llm.provider, "p1")                     # stayed put

    def test_permanent_error_retires_provider_immediately(self):
        class _Gone:
            status_code = 410

            def text(self, *a):
                exc = RuntimeError("model retired")
                exc.status_code = 410
                raise exc

        llm = self._wire(threshold=99)
        llm.backend = _Gone()
        self.assertEqual(llm.complete_text("s", "p"), "ok")
        self.assertIn("p1", llm._dead)         # never routed to again

    def test_auto_resolves_without_crash(self):
        # No provider keys in the unit-test env -> heuristic, never raises.
        llm = LLM(provider="auto", use_llm=True)
        self.assertIn(llm.status.split()[0], ("heuristic", "llm"))


class TestInputs(unittest.TestCase):
    def test_reads_text(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "notes.txt").write_text("target @nightowl_x on example.com")
            ctx = process_input_dir(d, vision=None)
            self.assertEqual(len(ctx["files"]), 1)
            self.assertTrue(any("nightowl" in n for n in ctx["notes"]))

    def test_skips_binary(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "x.exe").write_bytes(b"\x00\x01\x02")
            ctx = process_input_dir(d, vision=None)
            self.assertEqual(len(ctx["skipped"]), 1)


class TestConnectors(unittest.TestCase):
    def test_looks_blocked(self):
        self.assertTrue(_looks_blocked("Please complete this CAPTCHA challenge"))
        self.assertFalse(_looks_blocked("<html><body>normal results</body></html>"))

    def test_parse_ddg_fixture(self):
        html = ('<div class="result results_links web-result">'
                '<div class="links_main">'
                '<h2 class="result__title">'
                '<a class="result__a" href="https://example.com/page">'
                'Example Site</a></h2>'
                '<a class="result__url">example.com/page</a>'
                '<a class="result__snippet">A snippet about example.com</a>'
                '</div></div>')
        src = REGISTRY["duckduckgo"]
        results = _parse_ddg(html, src)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].title, "Example Site")
        self.assertIn("example.com", results[0].url)
        self.assertIn("snippet", results[0].snippet)

    def test_planmode_no_fetch(self):
        # plan-only fetcher never hits the network; run_source returns 'planned'
        g = Guardrails()
        f = Fetcher(g, live=False)
        run = run_source(REGISTRY["ahmia"], "leak", f)
        self.assertEqual(run.status, "planned")
        # nothing was blocked and, crucially, nothing was actually fetched:
        # the guardrail allowed the URL but the fetcher recorded a 'plan' event.
        self.assertEqual(g.summary()["blocked"], 0)
        self.assertTrue(any(e.action == "plan" for e in g.events))


class TestVisionParsing(unittest.TestCase):
    def test_structured_json(self):
        from blacknoir.agent import Agent
        out = ('{"description":"a painting","transcription":"@artby_luna",'
               '"names":["Luna A."],"usernames":["artbyluna"],'
               '"handles":["@artby_luna"],"domains":["artby-luna.example"],'
               '"emails":[],"watermarks":[],"platforms":["DA"]}')
        res = Agent._parse_vision(out)
        self.assertIn("Luna", res["analysis"])
        self.assertEqual(res["extracted"]["handles"], ["@artby_luna"])
        self.assertEqual(res["extracted"]["domains"], ["artby-luna.example"])

    def test_bad_json_fallback(self):
        from blacknoir.agent import Agent
        res = Agent._parse_vision("not json at all")
        self.assertEqual(res["extracted"], {})
        self.assertTrue(res["analysis"])

    def test_vision_entities_reach_graph(self):
        inv = Investigation(target="Who drew this", target_type="name",
                            surfaces=["public"], started="now")
        inv.input_context = {"images": [{"name": "a.png", "analysis": "x",
            "extracted": {"handles": ["@artby_luna"],
                          "domains": ["artby-luna.example"],
                          "names": ["Luna A."]}}]}
        correlate(inv)
        vals = {e.value for e in inv.entities}
        self.assertIn("@artby_luna", vals)
        self.assertIn("artby-luna.example", vals)  # .example TLD, injected directly


class TestReverseImage(unittest.TestCase):
    def test_prepared_links(self):
        from blacknoir.reverse_image import reverse_search
        g = Guardrails(); f = Fetcher(g, live=False)
        runs = reverse_search([{"name": "a.png", "path": __file__,
                                "subject_type": "artwork"}], f, "", False)
        keys = {r.source for run in runs for r in run.results}
        self.assertTrue({"google_lens", "yandex_images", "tineye",
                         "bing_visual"} <= keys)

    def test_planmode_no_upload(self):
        from blacknoir.reverse_image import reverse_search
        g = Guardrails()
        f = Fetcher(g, live=False)
        runs = reverse_search([{"name": "a.png", "path": __file__}], f, "", False)
        statuses = {r.source: r.status for r in runs}
        self.assertEqual(statuses.get("saucenao"), "planned")
        self.assertEqual(statuses.get("iqdb"), "planned")
        self.assertEqual(g.summary()["uploads"], 0)  # nothing uploaded

    def test_reverse_hosts_allowlisted(self):
        g = Guardrails()
        for u in ("https://saucenao.com/search.php?output_type=2",
                  "https://iqdb.org/"):
            self.assertTrue(g.can_fetch(u)[0])

    def test_parse_iqdb(self):
        from blacknoir.reverse_image import _parse_iqdb
        html = ('<table><tr><td>Best match</td></tr><tr><td>'
                '<a href="//danbooru.donmai.us/posts/123">img</a></td></tr>'
                '<tr><td>1000x1000 [Safe] 92% similarity</td></tr></table>')
        res = _parse_iqdb(html)
        self.assertEqual(len(res), 1)
        self.assertIn("danbooru", res[0].url)
        self.assertEqual(res[0].meta.get("similarity"), 92)


class TestIntentParsing(unittest.TestCase):
    def test_this_is_name(self):
        from blacknoir.intent import heuristic_parse
        p = heuristic_parse("This is jensen huang, search every secret details about him")
        self.assertEqual(p["subject"], "Jensen Huang")
        self.assertEqual(p["depth"], "deep")

    def test_command_stripping(self):
        from blacknoir.intent import heuristic_parse
        p = heuristic_parse("find everything about acme corp")
        self.assertNotIn("everything", p["subject"].lower())
        self.assertIn("acme", p["subject"].lower())
        self.assertEqual(p["depth"], "deep")

    def test_who_is_this_with_image(self):
        from blacknoir.intent import heuristic_parse
        p = heuristic_parse("Who is this", has_images=True)
        self.assertTrue(p["subject"].startswith("unknown subject"))
        self.assertEqual(p["subject_type"], "person")

    def test_plain_email_untouched(self):
        from blacknoir.intent import heuristic_parse
        p = heuristic_parse("john@example.com")
        self.assertEqual(p["subject"], "john@example.com")
        self.assertEqual(p["subject_type"], "email")


class TestReverseRouting(unittest.TestCase):
    def _statuses(self, subject_type):
        from blacknoir.reverse_image import reverse_search
        g = Guardrails(); f = Fetcher(g, live=False)
        imgs = [{"name": "x.png", "path": __file__, "subject_type": subject_type}]
        runs = reverse_search(imgs, f, "", False)
        return {r.source: r.status for r in runs}, runs

    def test_person_skips_art_dbs(self):
        st, runs = self._statuses("person")
        self.assertEqual(st.get("saucenao"), "skipped")
        self.assertEqual(st.get("iqdb"), "skipped")
        labels = " ".join(r.label for r in runs)
        self.assertIn("Face search", labels)

    def test_artwork_runs_art_dbs(self):
        st, _ = self._statuses("artwork")
        self.assertEqual(st.get("saucenao"), "planned")  # plan-only, would upload
        self.assertEqual(st.get("iqdb"), "planned")


class TestDarkwebQueries(unittest.TestCase):
    def test_terse_leak_oriented(self):
        from blacknoir.pipeline import _darkweb_queries
        qs = _darkweb_queries('"Elon Musk"', "deep")
        self.assertIn("Elon Musk", qs)                  # bare subject, unquoted
        self.assertTrue(any("leak" in q for q in qs))
        self.assertTrue(any("breach" in q for q in qs))
        # terse: no long natural-language phrasing
        self.assertTrue(all(len(q.split()) <= 4 for q in qs))


class TestChatRouting(unittest.TestCase):
    def test_search_detection(self):
        from blacknoir.chat import ChatSession
        f = ChatSession._looks_like_search
        self.assertTrue(f("who is ada lovelace"))
        self.assertTrue(f("investigate @nightowl"))
        self.assertTrue(f("search example.com"))
        self.assertFalse(f("what can you do?"))
        self.assertFalse(f("explain the dark web sources"))

    def test_input_scan_grounding(self):
        from blacknoir.chat import ChatSession
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "lead.txt").write_text("target @nightowl")
            s = ChatSession(use_llm=False, surfaces="public", input_dir=d)
            self.assertIn("lead.txt", s.input_summary)
            self.assertIn("1 file", s.input_summary)

    def test_input_scan_missing(self):
        from blacknoir.chat import ChatSession
        s = ChatSession(use_llm=False, input_dir="does-not-exist-xyz")
        self.assertIn("does not exist", s.input_summary)

    def test_session_builds(self):
        from blacknoir.chat import ChatSession
        s = ChatSession(use_llm=False, surfaces="public")
        self.assertEqual(s._surfaces(), ["public"])
        # command handling never raises
        self.assertIsNone(s._command("/live on"))
        self.assertTrue(s.live)
        self.assertEqual(s._command("/exit"), "exit")


class TestExternalTool(unittest.TestCase):
    def test_shellout_runs_and_parses(self):
        from blacknoir.connectors import run_source
        from blacknoir.config import REGISTRY
        with tempfile.TemporaryDirectory() as d:
            tool = Path(d) / "tool.py"
            tool.write_text("import sys\nprint('hit-' + sys.argv[1])\n"
                            "print('second line')\n")
            os.environ["TELEPATHY_CMD"] = f"{sys.executable} {tool} {{q}}"
            try:
                g = Guardrails(); f = Fetcher(g, live=True)
                run = run_source(REGISTRY["telepathy"], "acme", f)
            finally:
                del os.environ["TELEPATHY_CMD"]
        self.assertEqual(run.status, "ok")
        self.assertTrue(any("hit-acme" in r.title for r in run.results))
        self.assertTrue(any(e.action == "external-tool" for e in g.events))

    def test_not_configured_falls_back(self):
        from blacknoir.connectors import run_source
        from blacknoir.config import REGISTRY
        os.environ.pop("TELEPATHY_CMD", None)
        g = Guardrails(); f = Fetcher(g, live=True)
        run = run_source(REGISTRY["telepathy"], "acme", f)
        self.assertEqual(run.status, "planned")  # no clearnet API, no cmd


class TestRunbook(unittest.TestCase):
    def test_runbook_written(self):
        from blacknoir.runbook import render_runbook
        from blacknoir.models import SourceRun, SearchResult
        inv = Investigation(target="Acme", target_type="company",
                            surfaces=["darkweb"], started="now")
        inv.plan = {"queries": ["Acme leak", "Acme breach"]}
        inv.runs.append(SourceRun("torch", "Torch", "darkweb", "planned"))
        inv.runs.append(SourceRun("ahmia", "Ahmia.fi", "darkweb", "ok",
            results=[SearchResult("ahmia", "darkweb", "market",
                     url="http://abcdefghij234567.onion/x", is_onion=True)]))
        with tempfile.TemporaryDirectory() as d:
            p = render_runbook(inv, d)
            text = Path(p).read_text(encoding="utf-8")
        self.assertIn("Manual Runbook", text)
        self.assertIn("Torch", text)
        self.assertIn("Acme leak", text)
        self.assertIn(".onion", text)  # onion links listed for Tor Browser


class TestPreflightDetection(unittest.TestCase):
    """Read-only detection must never raise, regardless of host state."""
    def test_detection_callable(self):
        from blacknoir import preflight
        self.assertIsInstance(preflight.docker_installed(), bool)
        active, name = preflight.vpn_active()
        self.assertIsInstance(active, bool)
        self.assertIsInstance(name, str)

    def test_preflight_off_returns_true(self):
        from blacknoir.preflight import run_preflight
        noop = lambda m: None
        self.assertTrue(run_preflight("off", False, noop, noop))


if __name__ == "__main__":
    unittest.main(verbosity=2)


class TestPersonaVault(unittest.TestCase):
    def test_roundtrip(self):
        from blacknoir.persona import PersonaVault
        with tempfile.TemporaryDirectory() as d:
            path = str(Path(d) / "vault.json")
            v = PersonaVault(path)
            v.add("alias1")
            v.add_account("alias1", "telegram", "night_x", "n@x.com")
            v2 = PersonaVault(path)
            p = v2.get("ALIAS1")            # case-insensitive
            self.assertIsNotNone(p)
            self.assertEqual(p.accounts[0]["platform"], "telegram")
            self.assertTrue(v2.remove("alias1"))
            self.assertIsNone(PersonaVault(path).get("alias1"))

    def test_vault_stores_no_secrets(self):
        from blacknoir.persona import PersonaVault
        with tempfile.TemporaryDirectory() as d:
            path = str(Path(d) / "vault.json")
            v = PersonaVault(path); v.add("a")
            v.add_account("a", "email", "u", "e@x.com")
            text = Path(path).read_text()
            self.assertNotIn("password", text.lower())


class TestOpsec(unittest.TestCase):
    def test_warns_on_live_no_vpn(self):
        import blacknoir.persona as pmod
        orig = pmod.vpn_active
        pmod.vpn_active = lambda: (False, "")
        try:
            w = pmod.opsec_check(None, live=True)
            self.assertTrue(any("VPN" in x for x in w))
            self.assertTrue(any("Persona" in x for x in w))
            self.assertEqual(pmod.opsec_check(None, live=False), [])
        finally:
            pmod.vpn_active = orig


class TestTriage(unittest.TestCase):
    def test_urgent_ranks_first(self):
        from blacknoir.models import InboxItem
        from blacknoir.triage import triage
        items = [
            InboxItem("email", "n@y.com", "weekly digest", "mon", "some news"),
            InboxItem("email", "boss@x.com", "URGENT verify now", "today",
                      "please confirm asap"),
        ]
        ranked = triage(items, agent=None)
        self.assertIn("URGENT", ranked[0]["item"].subject)
        self.assertGreater(ranked[0]["score"], ranked[1]["score"])


class TestMessengerSend(unittest.TestCase):
    def test_send_refused_when_unconfigured(self):
        from blacknoir.messenger import get_provider
        # ensure no email creds in env for this check
        for k in ("EMAIL_ADDRESS", "GMAIL_ADDRESS", "EMAIL_APP_PASSWORD",
                  "GMAIL_APP_PASSWORD"):
            os.environ.pop(k, None)
        prov = get_provider("email")
        self.assertFalse(prov.available()[0])
        res = prov.send("x@y.com", "hi", lambda p: True)
        self.assertFalse(res.ok)

    def test_confirm_false_aborts(self):
        from blacknoir.messenger import EmailProvider
        os.environ["EMAIL_ADDRESS"] = "me@example.com"
        os.environ["EMAIL_APP_PASSWORD"] = "x"
        try:
            prov = EmailProvider()
            sent = {"n": 0}
            res = prov.send("t@x.com", "hi", lambda preview: False)  # decline
            self.assertFalse(res.ok)
            self.assertIn("not confirmed", res.detail)
        finally:
            os.environ.pop("EMAIL_ADDRESS", None)
            os.environ.pop("EMAIL_APP_PASSWORD", None)

    def test_providers_exist(self):
        from blacknoir.messenger import get_provider, PROVIDERS
        for name in PROVIDERS:
            self.assertIsNotNone(get_provider(name))
        self.assertIsNone(get_provider("whatsapp"))  # excluded platform


class TestSanitizer(unittest.TestCase):
    def test_never_fetches_links(self):
        from blacknoir.guardrails import sanitize_message_content
        r = sanitize_message_content(
            '<p>Hi <a href="http://evil.tld/x">click</a>'
            '<img src="http://track.tld/p.gif"></p>', is_html=True)
        self.assertEqual(r["text"], "Hi click")
        self.assertIn("http://evil.tld/x", r["links"])
        self.assertIn("http://track.tld/p.gif", r["images"])  # blocked, listed


class TestCommenting(unittest.TestCase):
    def test_youtube_provider_and_id(self):
        from blacknoir.messenger import get_provider, PROVIDERS, _yt_video_id
        self.assertIn("youtube", PROVIDERS)
        self.assertIsNotNone(get_provider("youtube"))
        self.assertEqual(
            _yt_video_id("https://www.youtube.com/watch?v=dQw4w9WgXcQ&t=5"),
            "dQw4w9WgXcQ")
        self.assertEqual(_yt_video_id("https://youtu.be/dQw4w9WgXcQ"),
                         "dQw4w9WgXcQ")

    def test_youtube_comment_needs_oauth(self):
        from blacknoir.messenger import YouTubeProvider
        for k in ("YOUTUBE_OAUTH_TOKEN",):
            os.environ.pop(k, None)
        res = YouTubeProvider().comment("dQw4w9WgXcQ", "hi", lambda p: True)
        self.assertFalse(res.ok)
        self.assertIn("OAUTH", res.detail.upper())

    def test_meta_has_comment(self):
        from blacknoir.messenger import get_provider
        for name in ("instagram", "facebook", "threads"):
            self.assertTrue(hasattr(get_provider(name), "comment"))


class TestPivots(unittest.TestCase):
    def test_phone_toolkit(self):
        from blacknoir.pivots import pivot_toolkit
        tk = pivot_toolkit("+852 5550 0100", "phone")
        self.assertIn("phone", tk)
        labels = " ".join(l for l, _ in tk["phone"])
        self.assertIn("Carrier", labels)
        self.assertTrue(any("hkjunkcall" in u for _, u in tk["phone"]))  # HK-specific

    def test_other_numeric_becomes_phone(self):
        from blacknoir.pivots import pivot_toolkit
        tk = pivot_toolkit("+852 5550 0100", "other")  # LLM mislabels as 'other'
        self.assertIn("phone", tk)

    def test_entity_toolkits_added(self):
        from blacknoir.pivots import pivot_toolkit
        from blacknoir.models import Entity
        tk = pivot_toolkit("acme.com", "domain", [Entity("x@acme.com", "email")])
        self.assertIn("domain", tk)
        self.assertIn("email", tk)

    def test_email_and_username(self):
        from blacknoir.pivots import pivot_toolkit
        self.assertIn("email", pivot_toolkit("a@b.com", "email"))
        self.assertIn("username", pivot_toolkit("@nightowl", "username"))
        self.assertIn("btc", pivot_toolkit(
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "btc"))


class TestEnrich(unittest.TestCase):
    def _fetcher(self, live=False):
        return Fetcher(Guardrails(), live=live)

    def test_plan_mode_no_network(self):
        # In plan mode get_json returns None; enrichers must not raise and
        # should report a non-'ok' status (planned/empty), never fetching.
        from blacknoir.enrich import (enrich_domain, enrich_ip,
                                      enrich_btc, enrich_username)
        f = self._fetcher(live=False)
        for run in (enrich_domain("example.com", f), enrich_ip("1.1.1.1", f),
                    enrich_btc("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", f),
                    enrich_username("torvalds", f)):
            self.assertNotEqual(run.status, "ok")
            self.assertEqual(run.results, [])

    def test_enrichment_hosts_allowlisted(self):
        g = Guardrails()
        for host in ("crt.sh", "dns.google", "archive.org",
                     "internetdb.shodan.io", "blockstream.info",
                     "api.github.com", "www.reddit.com"):
            self.assertTrue(g.can_fetch(f"https://{host}/x")[0], host)

    def test_onion_still_forbidden(self):
        # enrichment must never relax the onion ban
        self.assertFalse(Guardrails().can_fetch("http://abc.onion/")[0])

    def test_run_enrichment_selects_by_type(self):
        from blacknoir.enrich import run_enrichment
        from blacknoir.models import Investigation
        inv = Investigation(target="acme.com", target_type="domain",
                            surfaces=["public"], started="now")
        runs = run_enrichment("acme.com", "domain", inv, self._fetcher(False))
        self.assertEqual(len(runs), 1)
        self.assertEqual(runs[0].source, "enrich_domain")

    def test_run_enrichment_skips_untyped(self):
        from blacknoir.enrich import run_enrichment
        from blacknoir.models import Investigation
        inv = Investigation(target="a name", target_type="name",
                            surfaces=["public"], started="now")
        self.assertEqual(run_enrichment("a name", "name", inv,
                                        self._fetcher(False)), [])


class TestExif(unittest.TestCase):
    def test_gps_conversion(self):
        from blacknoir.inputs import _gps_to_deg
        # 22°17'... N should be positive; S/W negative
        self.assertAlmostEqual(_gps_to_deg((22, 17, 0), "N"),
                               22 + 17 / 60.0, places=4)
        self.assertLess(_gps_to_deg((114, 9, 0), "W"), 0)
        self.assertIsNone(_gps_to_deg(None, "N"))

    def test_extract_exif_safe_on_missing(self):
        from blacknoir.inputs import extract_exif
        # non-image / missing path must return {} not raise
        self.assertEqual(extract_exif("does_not_exist.jpg"), {})


class TestUsernameSweep(unittest.TestCase):
    def test_detect_status_sites(self):
        from blacknoir.username_sweep import _detect
        self.assertEqual(_detect(200, "", None), "found")
        self.assertEqual(_detect(404, "", None), "not_found")
        self.assertEqual(_detect(500, "", None), "unknown")

    def test_detect_marker_sites(self):
        from blacknoir.username_sweep import _detect
        self.assertEqual(_detect(200, "has g_rgProfileData here", "g_rgProfileData"),
                         "found")
        self.assertEqual(_detect(200, "generic page", "g_rgProfileData"),
                         "not_found")
        self.assertEqual(_detect(None, None, None), "error")

    def test_plan_mode_planned(self):
        from blacknoir.username_sweep import sweep_username
        f = Fetcher(Guardrails(), live=False)
        self.assertEqual(sweep_username("torvalds", f).status, "planned")

    def test_rejects_non_handle(self):
        from blacknoir.username_sweep import sweep_username
        f = Fetcher(Guardrails(), live=False)
        self.assertEqual(sweep_username("a name/with spaces", f).status, "skipped")

    def test_hosts_allowlisted(self):
        from blacknoir.username_sweep import SWEEP_HOSTS
        g = Guardrails()
        for h in SWEEP_HOSTS:
            self.assertTrue(g.can_fetch(f"https://{h}/x")[0], h)

    def test_audit_log_complete_under_threads(self):
        # the safety guarantee: parallel probes must not drop or corrupt
        # audit events. Fire many can_fetch/note calls across threads and
        # assert every one is recorded.
        from concurrent.futures import ThreadPoolExecutor
        g = Guardrails()
        N = 500
        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(lambda i: g.can_fetch(f"https://github.com/u{i}"),
                          range(N)))
        self.assertEqual(len(g.events), N)
        self.assertTrue(all(e.action == "allow" for e in g.events))

    def test_thread_local_sessions_distinct(self):
        # each thread must get its own requests.Session (never shared).
        # Hold the actual Session OBJECTS (not id()) and keep both threads alive
        # at once via a barrier: comparing ids of sessions from already-dead
        # threads is unreliable because a freed Session's address can be reused
        # by the next thread's Session, giving a false identity collision.
        import threading
        f = Fetcher(Guardrails(), live=True)
        sessions = {}
        barrier = threading.Barrier(2)

        def grab(name):
            s = f._session          # create/fetch this thread's session
            barrier.wait()          # both sessions now coexist — no address reuse
            sessions[name] = s      # retain the object so it stays alive

        t1 = threading.Thread(target=grab, args=("a",))
        t2 = threading.Thread(target=grab, args=("b",))
        t1.start(); t2.start()
        t1.join(); t2.join()
        # distinct Session instances per thread
        self.assertIsNot(sessions["a"], sessions["b"])


class TestMultiAgent(unittest.TestCase):
    """Multi-agent planning panel: fan out across keyed providers, union
    queries, exclude Ollama by default."""

    def setUp(self):
        self._saved = {k: os.environ.get(k) for k in
                       ("GOOGLE_API_KEY", "BLACKNOIR_MULTI_AGENT",
                        "BLACKNOIR_PANEL_OLLAMA", "BLACKNOIR_PANEL_SIZE")}

    def tearDown(self):
        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def test_ollama_excluded_from_panel_by_default(self):
        from blacknoir.llm import available_providers
        os.environ["GOOGLE_API_KEY"] = "x"
        os.environ.pop("BLACKNOIR_PANEL_OLLAMA", None)
        provs = available_providers()
        self.assertIn("google", provs)
        self.assertNotIn("ollama", provs)  # slow/local: opt-in only

    def test_multi_agent_toggle(self):
        from blacknoir.llm import multi_agent_enabled
        os.environ.pop("BLACKNOIR_MULTI_AGENT", None)
        self.assertTrue(multi_agent_enabled())        # default on
        os.environ["BLACKNOIR_MULTI_AGENT"] = "0"
        self.assertFalse(multi_agent_enabled())

    def test_panel_size_parsing(self):
        from blacknoir.llm import panel_size, DEFAULT_PANEL_SIZE
        self.assertEqual(panel_size("3"), 3)
        self.assertEqual(panel_size("1"), 1)
        self.assertGreater(panel_size("all"), 100)   # no practical cap
        os.environ.pop("BLACKNOIR_PANEL_SIZE", None)
        self.assertEqual(panel_size(), DEFAULT_PANEL_SIZE)  # default
        os.environ["BLACKNOIR_PANEL_SIZE"] = "2"
        self.assertEqual(panel_size(), 2)

    def test_new_providers_registered(self):
        from blacknoir.llm import SPECS, AUTO_ORDER
        for p in ("openrouter", "siliconflow", "cloudflare"):
            self.assertIn(p, SPECS)
            self.assertIn(p, AUTO_ORDER)
        self.assertNotIn("zenmux", SPECS)  # removed

    def test_merge_plans_unions_sources_and_dedupes_queries(self):
        from blacknoir.agent import Agent
        from blacknoir.config import REGISTRY
        a = Agent(use_llm=False)  # heuristic; we test _merge_plans directly
        plans = [
            {"selected": [{"key": "serper", "why": "a"}], "queries": ["q1", "q2"]},
            {"selected": [{"key": "serper", "why": "b"},
                          {"key": "github", "why": "c"}], "queries": ["q2", "q3"]},
        ]

        class _Inv:
            target = "t"
        merged = a._merge_plans(plans, list(REGISTRY.values()), _Inv())
        self.assertEqual([s["key"] for s in merged["selected"]],
                         ["serper", "github"])            # unioned, deduped
        self.assertEqual(merged["queries"], ["q1", "q2", "q3"])  # deduped, ordered
        self.assertIn("multi-agent", merged["mode"])


class TestDocMeta(unittest.TestCase):
    def test_docx_core_props(self):
        import zipfile
        from blacknoir.inputs import extract_doc_meta
        d = tempfile.mkdtemp()
        p = os.path.join(d, "t.docx")
        core = ('<?xml version="1.0"?><cp:coreProperties '
                'xmlns:cp="http://schemas.openxmlformats.org/package/2006/'
                'metadata/core-properties" xmlns:dc="http://purl.org/dc/'
                'elements/1.1/"><dc:creator>Jane Doe</dc:creator>'
                '<dc:title>Plan</dc:title></cp:coreProperties>')
        with zipfile.ZipFile(p, "w") as z:
            z.writestr("docProps/core.xml", core)
        meta = extract_doc_meta(p, ".docx")
        self.assertEqual(meta.get("author"), "Jane Doe")
        self.assertEqual(meta.get("title"), "Plan")

    def test_pdf_info_dict(self):
        from blacknoir.inputs import extract_doc_meta
        d = tempfile.mkdtemp()
        p = os.path.join(d, "t.pdf")
        with open(p, "wb") as fh:
            fh.write(b"%PDF-1.4\n1 0 obj<< /Author (John Smith) "
                     b"/Creator (Word) >>endobj")
        meta = extract_doc_meta(p, ".pdf")
        self.assertEqual(meta.get("author"), "John Smith")

    def test_missing_returns_empty(self):
        from blacknoir.inputs import extract_doc_meta
        self.assertEqual(extract_doc_meta("nope.docx", ".docx"), {})


class TestKeyedEnrichers(unittest.TestCase):
    def test_keyed_skipped_without_key(self):
        # run_enrichment must not invoke keyed APIs when env keys are absent
        from blacknoir.enrich import run_enrichment
        from blacknoir.models import Investigation
        for var in ("SHODAN_API_KEY", "NUMVERIFY_API_KEY", "INTELX_API_KEY"):
            os.environ.pop(var, None)
        inv = Investigation(target="1.1.1.1", target_type="ip",
                            surfaces=["public"], started="now")
        runs = run_enrichment("1.1.1.1", "ip", inv, Fetcher(Guardrails(), False))
        sources = {r.source for r in runs}
        self.assertIn("enrich_ip", sources)          # keyless always
        self.assertNotIn("enrich_shodan", sources)   # keyed, no key -> skipped


class TestSurfaceEngineReachability(unittest.TestCase):
    """Regressions for a live run that searched the surface web and showed
    nothing: DuckDuckGo was refused by our own allow-list, the qualifier was
    truncated to a stub, alternate names were discarded, and the dead engine
    left no trace in the report."""

    def test_query_endpoint_host_is_allowlisted(self):
        # A source advertising one host and querying another (DuckDuckGo:
        # duckduckgo.com vs html.duckduckgo.com) was blocked on every query.
        g = Guardrails()
        for key, src in REGISTRY.items():
            if not src.query_url or src.query_url.startswith("local://"):
                continue
            url = src.query_url.replace("{q}", "test")
            ok, reason = g.can_fetch(url)
            self.assertTrue(ok, f"{key}: own query endpoint refused ({reason})")

    def test_duckduckgo_query_url_allowed(self):
        ok, _ = Guardrails().can_fetch(
            "https://html.duckduckgo.com/html/?q=test")
        self.assertTrue(ok)

    def test_unknown_host_still_blocked(self):
        ok, reason = Guardrails().can_fetch("https://evil.example.com/x")
        self.assertFalse(ok)
        self.assertIn("host-not-allowlisted", reason)

    def test_abbreviation_does_not_truncate_context(self):
        # "St. Brendon College ..." used to collapse to "St", which then
        # failed the length guard and left context empty.
        from blacknoir.intent import heuristic_parse
        p = heuristic_parse('Search "Kenmen Cho" from St. Brendon College '
                            '& High School in Hong Kong')
        self.assertEqual(p["context"],
                         "St. Brendon College & High School in Hong Kong")

    def test_trailing_parenthetical_not_absorbed(self):
        from blacknoir.intent import heuristic_parse
        p = heuristic_parse('Search "Ann Wu" from Mt. Sinai Hospital '
                            '(comprehensive deep search, every public detail)')
        self.assertEqual(p["context"], "Mt. Sinai Hospital")

    def test_all_quoted_names_kept_as_aliases(self):
        from blacknoir.intent import heuristic_parse
        p = heuristic_parse('Search "Kenmen Cho" whose full name is "\u6797\u6c38\u5091" '
                            'or "Lam Wing Kit" from St. Brendon College')
        self.assertEqual(p["subject"], "Kenmen Cho")
        self.assertEqual(p["aliases"], ["\u6797\u6c38\u5091", "Lam Wing Kit"])

    def test_aliases_lead_recon_without_displacing_probes(self):
        from blacknoir.deepsearch import _recon_queries, RECON_QUERIES
        qs = _recon_queries("Kenmen Cho", "St. Brendon College", "name",
                            None, ["\u6797\u6c38\u5091", "Lam Wing Kit"])
        self.assertTrue(qs[0].startswith("\u6797\u6c38\u5091"))
        # The invariant this guards is that aliases EXTEND the sweep rather
        # than displacing the broadening probes \u2014 asserted directly, because a
        # fixed total breaks whenever the per-alias query count changes for a
        # deliberate reason (an alias now also goes out un-qualified).
        self.assertGreater(len(qs), RECON_QUERIES)
        self.assertTrue(any("LinkedIn" in q for q in qs))
        self.assertTrue(any(q.startswith("Kenmen Cho") for q in qs),
                        "the primary name's own probes were displaced")
        # Each alias is tried ALONE as well as context-qualified: a
        # native-script name is more unique than its romanisation, and
        # appending the org to every query is what buries the person under
        # pages about the organisation.
        self.assertIn("\u6797\u6c38\u5091", qs)
        # unchanged when no aliases are supplied
        self.assertEqual(len(_recon_queries("Alex Marsh", "AI security", "name")),
                         RECON_QUERIES)

    def test_alias_match_counts_as_on_target(self):
        from blacknoir.entities import is_about_target
        aliases = ["\u6797\u6c38\u5091", "Lam Wing Kit"]
        self.assertTrue(is_about_target("SBC \u6797\u6c38\u5091 alumni", "Kenmen Cho",
                                        "St. Brendon", aliases))
        self.assertFalse(is_about_target("Kenneth Cho olive oil", "Kenmen Cho",
                                         "St. Brendon", aliases))

    def test_guardrail_refusal_is_named_not_silent(self):
        # A refusal by our OWN allow-list must be distinguishable from a
        # network timeout, or a config bug reads as "target has no footprint".
        f = Fetcher(Guardrails(), live=True)
        self.assertIsNone(f.get("https://evil.example.com/x"))
        self.assertTrue(f.last_error[1].startswith("guardrail:"))

    def test_dead_engine_gets_a_visible_run(self):
        # The deep loop merges engines into one anonymous pile; an engine that
        # never returned anything must still appear as its own row.
        from blacknoir.deepsearch import DeepSearchState, _as_runs, _health
        st = DeepSearchState(target="X")
        src = REGISTRY["duckduckgo"]
        _health(st, src, "blocked", "refused by local guardrail")
        rows = {r.source: r for r in _as_runs(st)}
        self.assertIn("deepsearch_duckduckgo", rows)
        self.assertEqual(rows["deepsearch_duckduckgo"].status, "blocked")


class TestReasoningModelOutput(unittest.TestCase):
    """A reasoning model narrates before answering. The narration contains
    braces and schema echoes, so naive first-{ to last-} slicing fails — and
    the callers used to swallow that, silently degrading to heuristics."""

    def test_extracts_json_after_reasoning_prose(self):
        from blacknoir.llm import json_from_model
        out = ('Okay, the user wants {subject}. Let me think. The schema is '
               '{"subject":"...","context":"..."} so I should fill it in.\n\n'
               'Final answer:\n{"subject":"Kenmen Cho","context":"SBC"}')
        self.assertEqual(json_from_model(out),
                         {"subject": "Kenmen Cho", "context": "SBC"})

    def test_prefers_fenced_block(self):
        from blacknoir.llm import json_from_model
        out = ('thinking {"subject":"WRONG"} ...\n```json\n'
               '{"subject":"RIGHT"}\n```\n')
        self.assertEqual(json_from_model(out)["subject"], "RIGHT")

    def test_brace_inside_string_does_not_close_object(self):
        from blacknoir.llm import json_from_model
        self.assertEqual(json_from_model('{"a":"} not the end","b":2}'),
                         {"a": "} not the end", "b": 2})

    def test_truncated_object_is_rejected_not_half_parsed(self):
        # Half a JSON object is worse than none: it yields a confident but
        # wrong subject. Reject so the heuristic parser takes over.
        from blacknoir.llm import json_from_model
        self.assertIsNone(json_from_model('reasoning...\n{"subject":"Kenmen'))

    def test_no_json_at_all(self):
        from blacknoir.llm import json_from_model
        self.assertIsNone(json_from_model("I cannot answer that."))
        self.assertIsNone(json_from_model(""))
        self.assertIsNone(json_from_model(None))

    def test_retired_nvidia_model_is_not_the_default(self):
        # meta/llama-3.1-70b-instruct answers HTTP 410 Gone and sat first in
        # the failover chain, so every fallback landed on a dead model.
        from blacknoir.llm import SPECS
        self.assertNotEqual(SPECS["nvidia"].default_model,
                            "meta/llama-3.1-70b-instruct")


class TestSourceVisibility(unittest.TestCase):
    """A source missing from the report is indistinguishable from one that ran
    and found nothing — which reads as an absence of findings."""

    def test_unqueried_source_is_counted_separately(self):
        from blacknoir.report import _stat_cards
        inv = Investigation(target="x", target_type="name",
                            surfaces=["public"], started="now")
        inv.runs = [SourceRun("a", "A", "public", "ok"),
                    SourceRun("b", "B", "darkweb", "skipped",
                              detail="not queried: needs KEY")]
        html = _stat_cards(inv)
        self.assertIn("Not queried", html)
        # the skipped source must NOT inflate the "queried" count
        self.assertRegex(html, r"Sources queried.*?>1<")

    def test_skipped_source_still_renders_in_the_table(self):
        from blacknoir.report import _runs_table
        inv = Investigation(target="x", target_type="name",
                            surfaces=["darkweb"], started="now")
        inv.runs = [SourceRun("dehashed", "DeHashed", "darkweb", "skipped",
                              detail="not queried: needs DEHASHED_API_KEY")]
        html = _runs_table(inv)
        self.assertIn("DeHashed", html)
        self.assertIn("DEHASHED_API_KEY", html)


class TestClusterVerdictVsFailure(unittest.TestCase):
    """A model that looks and finds nobody has ANSWERED. Reporting that as an
    unusable model output overwrites a correct negative with weaker heuristics
    and tells the operator something false about the run."""

    def _state(self):
        from blacknoir.deepsearch import DeepSearchState
        return DeepSearchState(target="Kenmen Cho", context="SBC Hong Kong")

    def _agent(self, payload, n=1):
        """A stand-in for Agent with the same fan-out contract: `n` models each
        returning `payload`, parsed exactly as the real fan-out parses."""
        from blacknoir.llm import json_from_model

        class _A:
            enabled = True
            panel_n = n

            def _complete(self, *a, **k):
                return payload

            def fanout_json(self, system, prompt, max_tokens=1200, **k):
                d = json_from_model(payload)
                return [d for _ in range(n)] if isinstance(d, dict) and d else []
        return _A()

    def _results(self, n=3):
        return [SearchResult("serper", "public", "Wing Lam %d" % i,
                             "https://x/%d" % i, "s") for i in range(n)]

    def test_empty_candidate_list_is_a_verdict_not_a_failure(self):
        from blacknoir.deepsearch import cluster_llm
        st = self._state()
        out = cluster_llm(st, self._results(),
                          self._agent('{"candidates":[],"discarded":3}'))
        self.assertEqual(out, [])          # [] not None
        self.assertTrue(any("about someone else" in n for n in st.notes))

    def test_unusable_output_is_still_none(self):
        from blacknoir.deepsearch import cluster_llm
        st = self._state()
        self.assertIsNone(cluster_llm(st, self._results(),
                                      self._agent("I cannot do that.")))

    def test_note_distinguishes_verdict_from_fallback(self):
        from blacknoir.deepsearch import cluster
        st = self._state()
        cluster(st, self._results(), self._agent('{"candidates":[],"discarded":3}'))
        self.assertTrue(any("NOT the model" in n for n in st.notes))
        self.assertFalse(any("no LLM available" in n for n in st.notes))

        st2 = self._state()
        cluster(st2, self._results(), self._agent("garbage"))
        self.assertTrue(any("no LLM available" in n for n in st2.notes))


class TestBingParser(unittest.TestCase):
    """Bing must be read by its own parser: the generic anchor scraper walks
    nav/stylesheet/related-search links and produced the off-query rows that
    got Bing removed in the first place."""

    _HTML = ('<html><body><ol id="b_results">'
             '<li class="b_algo"><link rel="stylesheet" href="https://r.bing.com/x.css"/>'
             '<h2><a href="https://www.bing.com/ck/a?!&amp;&amp;p=1&amp;u='
             'a1aHR0cHM6Ly9naXRodWIuY29tL2FtYXJzaC1zZWM&amp;ntb=1">'
             'AMarsh-Sec (Alex Marsh) &middot; GitHub</a></h2>'
             '<div class="b_caption"><p>Security research profile.</p></div></li>'
             '<li class="b_algo"><h2><a href="https://example.org/plain">'
             'Plain result</a></h2><p>No redirect wrapper.</p></li>'
             '</ol>'
             '<div class="b_rs"><a href="https://www.bing.com/search?q=related">'
             'related search noise</a></div></body></html>')

    def _src(self):
        from blacknoir.config import REGISTRY
        return REGISTRY["bing"]

    def test_extracts_only_result_containers(self):
        from blacknoir.connectors import _parse_bing
        out = _parse_bing(self._HTML, self._src())
        self.assertEqual(len(out), 2)                      # not the b_rs link
        self.assertNotIn("related search noise",
                         " ".join(r.title for r in out))

    def test_unwraps_click_redirect_to_real_url(self):
        from blacknoir.connectors import _parse_bing
        out = _parse_bing(self._HTML, self._src())
        self.assertEqual(out[0].url, "https://github.com/amarsh-sec")
        self.assertIn("AMarsh-Sec", out[0].title)
        self.assertIn("Security research", out[0].snippet)

    def test_plain_url_passes_through(self):
        from blacknoir.connectors import _parse_bing
        self.assertEqual(_parse_bing(self._HTML, self._src())[1].url,
                         "https://example.org/plain")

    def test_unwrap_is_safe_on_junk(self):
        from blacknoir.connectors import _unwrap_bing_url
        for u in ("https://example.com/a",
                  "https://www.bing.com/ck/a?u=notbase64!!",
                  "https://www.bing.com/ck/a",
                  "not a url"):
            self.assertIsInstance(_unwrap_bing_url(u), str)

    def test_bing_results_still_face_the_relevance_filter(self):
        # Bing honours the query only ~1/3 of the time (measured), so its rows
        # must remain subject to on-target filtering rather than being trusted.
        from blacknoir.entities import is_about_target
        self.assertFalse(is_about_target(
            "Xbox wireless controller drift https://answers.microsoft.com/x",
            "Alex Marsh", "AI security"))


class TestBingDecoyDefence(unittest.TestCase):
    """Bing serves randomised decoy SERPs: well-formed results with nothing to
    do with the query. They are indistinguishable from findings once they are
    in the pipeline, so they must be caught at the connector boundary."""

    _RSS = ('<?xml version="1.0" encoding="utf-8" ?><rss version="2.0"><channel>'
            '<title>Bing: AMarsh-Sec github</title>'
            '<item><title>AMarsh-Sec (Alex Marsh) &#183; GitHub</title>'
            '<link>https://github.com/amarsh-sec</link>'
            '<description>Security research &amp; experiments.</description></item>'
            '<item><title>Vulnerability Experiments</title>'
            '<link>https://amarsh-sec.github.io/x</link>'
            '<description>Write-ups.</description></item>'
            '</channel></rss>')

    def _src(self):
        from blacknoir.config import REGISTRY
        return REGISTRY["bing"]

    def test_rss_is_the_registered_parser(self):
        from blacknoir.connectors import _PARSERS, _parse_bing_rss
        self.assertIs(_PARSERS["bing"], _parse_bing_rss)

    def test_rss_query_url_requests_the_feed(self):
        self.assertIn("format=rss", self._src().query_url)

    def test_rss_parses_real_destination_urls(self):
        from blacknoir.connectors import _parse_bing_rss
        out = _parse_bing_rss(self._RSS, self._src())
        self.assertEqual(len(out), 2)
        self.assertEqual(out[0].url, "https://github.com/amarsh-sec")
        self.assertIn("AMarsh-Sec", out[0].title)
        self.assertNotIn("bing.com", out[0].url)      # no ck/a click-wrapper

    def test_decoy_detected_when_no_query_term_appears(self):
        from blacknoir.connectors import _looks_like_decoy
        decoy = [SearchResult("bing", "public", "MOSH | A Protein Bar",
                              "https://moshlife.com", "brain food"),
                 SearchResult("bing", "public", "Leo Horoscopes Daily",
                              "https://horoscope.com", "astrology")]
        self.assertTrue(_looks_like_decoy(decoy, "Jensen Huang NVIDIA"))

    def test_real_results_are_not_flagged_as_decoy(self):
        from blacknoir.connectors import _looks_like_decoy, _parse_bing_rss
        out = _parse_bing_rss(self._RSS, self._src())
        self.assertFalse(_looks_like_decoy(out, "AMarsh-Sec github"))

    def test_cjk_query_terms_survive_tokenisation(self):
        from blacknoir.connectors import _query_terms, _looks_like_decoy
        self.assertIn("\u8056\u6587\u5fb7\u66f8\u9662",
                      _query_terms("\u8056\u6587\u5fb7\u66f8\u9662"))
        hit = [SearchResult("bing", "public", "\u8056\u6587\u5fb7\u66f8\u9662 - Wikipedia",
                            "https://zh.wikipedia.org/x", "")]
        self.assertFalse(_looks_like_decoy(hit, "\u8056\u6587\u5fb7\u66f8\u9662"))

    def test_decoy_check_only_applies_to_flagged_engines(self):
        # Serper is trusted; a narrow allow-list keeps the check from silently
        # discarding a real result set from an engine that does not decoy.
        from blacknoir.connectors import _DECOY_PRONE
        self.assertEqual(_DECOY_PRONE, {"bing"})

    def test_empty_inputs_are_not_decoys(self):
        from blacknoir.connectors import _looks_like_decoy
        self.assertFalse(_looks_like_decoy([], "anything"))
        self.assertFalse(_looks_like_decoy(
            [SearchResult("bing", "public", "t", "https://x", "")], ""))


class TestMultiAgentSearch(unittest.TestCase):
    """The search half of the panel: planning fans out to widen recall, the
    search steps fan out to make a JUDGEMENT robust. One model's bad round
    should not silently decide an identity."""

    def _results(self, n=6):
        return [SearchResult("serper", "public", "r%d" % i,
                             "https://x/%d" % i, "s%d" % i) for i in range(n)]

    # -- clustering votes ---------------------------------------------------

    def test_same_person_merges_across_models_by_shared_evidence(self):
        from blacknoir.deepsearch import _merge_cluster_votes
        datas = [
            {"candidates": [{"label": "Wing Lam, analyst", "evidence": [0, 1],
                             "context_match": 0.8}]},
            {"candidates": [{"label": "Kenneth Cho (Rotterdam)",
                             "evidence": [1, 2], "context_match": 0.6,
                             "org": "Blue Harbour"}]},
        ]
        out = _merge_cluster_votes(datas, self._results())
        self.assertEqual(len(out), 1)            # different labels, same person
        self.assertEqual(out[0]["evidence"], [0, 1, 2])
        self.assertEqual(out[0]["_votes"], 2)
        self.assertAlmostEqual(out[0]["context_match"], 0.7, places=6)
        self.assertEqual(out[0]["org"], "Blue Harbour")

    def test_distinct_people_stay_separate(self):
        from blacknoir.deepsearch import _merge_cluster_votes
        datas = [{"candidates": [
            {"label": "A", "evidence": [0], "context_match": 0.9},
            {"label": "B", "evidence": [3], "context_match": 0.2}]}]
        out = _merge_cluster_votes(datas, self._results())
        self.assertEqual(len(out), 2)

    def test_agreed_candidates_rank_above_lone_guesses(self):
        from blacknoir.deepsearch import _merge_cluster_votes
        datas = [
            {"candidates": [{"label": "Agreed", "evidence": [0],
                             "context_match": 0.5}]},
            {"candidates": [{"label": "Agreed", "evidence": [0],
                             "context_match": 0.5},
                            {"label": "Lone", "evidence": [4],
                             "context_match": 0.99}]},
        ]
        out = _merge_cluster_votes(datas, self._results())
        self.assertEqual(out[0]["label"], "Agreed")   # 2 votes beats 0.99 alone
        self.assertEqual(out[0]["_votes"], 2)
        self.assertEqual(out[1]["_votes"], 1)

    def test_seed_queries_are_unioned_not_intersected(self):
        from blacknoir.deepsearch import _merge_cluster_votes
        datas = [{"candidates": [{"label": "X", "evidence": [0],
                                  "queries": ["q1", "q2"]}]},
                 {"candidates": [{"label": "X", "evidence": [0],
                                  "queries": ["q2", "q3"]}]}]
        out = _merge_cluster_votes(datas, self._results())
        self.assertEqual(out[0]["queries"], ["q1", "q2", "q3"])

    # -- evidence votes -----------------------------------------------------

    def test_belongs_needs_a_majority(self):
        from blacknoir.deepsearch import _merge_judgements
        datas = [{"belongs": [0, 1]}, {"belongs": [0, 2]}, {"belongs": [0, 1]}]
        out = _merge_judgements(datas, 6)
        self.assertEqual(out["belongs"], [0, 1])   # 2 dropped: only 1 of 3
        self.assertEqual(out["votes"]["needed"], 2)

    def test_single_model_keeps_its_own_verdict(self):
        from blacknoir.deepsearch import _merge_judgements
        out = _merge_judgements([{"belongs": [0, 3]}], 6)
        self.assertEqual(out["belongs"], [0, 3])

    def test_next_queries_are_unioned_so_a_lone_lead_survives(self):
        from blacknoir.deepsearch import _merge_judgements
        datas = [{"next_queries": ["a"]}, {"next_queries": ["b"]},
                 {"next_queries": ["a"]}]
        self.assertEqual(_merge_judgements(datas, 3)["next_queries"], ["a", "b"])

    def test_saturation_requires_unanimity(self):
        from blacknoir.deepsearch import _merge_judgements
        self.assertFalse(_merge_judgements(
            [{"saturated": True}, {"saturated": False}], 3)["saturated"])
        self.assertTrue(_merge_judgements(
            [{"saturated": True}, {"saturated": True}], 3)["saturated"])

    def test_out_of_range_indices_are_ignored(self):
        from blacknoir.deepsearch import _merge_judgements
        out = _merge_judgements([{"belongs": [0, 99, -1, "x"]}], 3)
        self.assertEqual(out["belongs"], [0])

    def test_attributes_union_across_models(self):
        from blacknoir.deepsearch import _merge_judgements
        datas = [{"new_attributes": {"orgs": ["Acme"]}},
                 {"new_attributes": {"orgs": ["acme", "Globex"], "roles": ["Eng"]}}]
        out = _merge_judgements(datas, 3)["new_attributes"]
        self.assertEqual(out["orgs"], ["Acme", "Globex"])   # case-insensitive
        self.assertEqual(out["roles"], ["Eng"])

    # -- panel sizing -------------------------------------------------------

    def test_default_panel_is_three(self):
        from blacknoir.llm import panel_size, DEFAULT_PANEL_SIZE
        self.assertEqual(DEFAULT_PANEL_SIZE, 3)
        self.assertEqual(panel_size(None), 3)

    def test_all_uncaps_the_panel(self):
        from blacknoir.llm import panel_size
        for word in ("all", "max"):
            self.assertGreater(panel_size(word), 100)

    def test_explicit_size_wins(self):
        from blacknoir.llm import panel_size
        self.assertEqual(panel_size("5"), 5)
        self.assertEqual(panel_size("1"), 1)


class TestHallucinationRegression(unittest.TestCase):
    """Guards for the three 'hallucination' fixes: junk phones, ungrounded
    confidence, and operator candidate-focus."""

    def _entities(self, snippet):
        inv = Investigation(target="Jessica Wong", target_type="person",
                            surfaces=["public"], started="now")
        inv.runs.append(SourceRun(
            "serper", "Serper", "public", "ok",
            results=[SearchResult("serper", "public", "Jessica Wong",
                                  snippet=snippet)]))
        correlate(inv)
        return {e.value for e in inv.entities if e.kind == "phone"}

    def test_ids_and_dateranges_are_not_phones(self):
        phones = self._entities(
            "Jessica Wong id Q139770117, slug _424086952, years 2016 - 2018, "
            "tel +852 5550 0100")
        # Wikidata Q-id and URL slug must not become phone nodes
        self.assertNotIn("139770117", phones)
        self.assertNotIn("424086952", phones)
        # a year range must not become an 8-digit phone
        self.assertFalse(any("2016" in p and "2018" in p for p in phones),
                         f"date range leaked as phone: {phones}")

    def test_real_formatted_phone_still_extracts(self):
        phones = self._entities("reach Jessica Wong at +852 5550 0100 anytime")
        self.assertTrue(any("5550" in p and "0100" in p for p in phones),
                        f"formatted phone dropped: {phones}")

    def test_focus_pins_one_and_rules_out_the_rest(self):
        from blacknoir.deepsearch import focus, MIN_CONTEXT_MATCH
        prev = {"mode": "llm", "candidates": [
            {"label": "A", "context_match": 0.10, "outcome": "dry",
             "evidence": []},
            {"label": "B", "context_match": 0.0, "outcome": "skipped",
             "evidence": []},
            {"label": "C", "context_match": 0.0, "outcome": "skipped",
             "evidence": []}]}
        # surfaces=[] -> no sources -> returns before any network deep-dive
        state, _ = focus(prev, 2, "T", "ctx", "name", [], None, None)
        outs = {c.label: c.outcome for c in state.candidates}
        self.assertEqual(outs["B"], "pending")       # the pick is pursued
        self.assertEqual(outs["A"], "excluded")      # the rest are ruled out
        self.assertEqual(outs["C"], "excluded")
        self.assertGreaterEqual(state.candidates[1].context_match,
                                MIN_CONTEXT_MATCH)

    def test_focus_rejects_out_of_range(self):
        from blacknoir.deepsearch import focus
        prev = {"candidates": [
            {"label": "A", "context_match": 0.1, "outcome": "dry",
             "evidence": []}]}
        state, _ = focus(prev, 5, "T", "", "name", [], None, None)
        self.assertTrue(any("range" in n for n in state.notes))


class TestNoiseDomainFilter(unittest.TestCase):
    """Fix B: platform/infra domains never become graph nodes."""

    def test_platform_domains_dropped(self):
        inv = Investigation(target="Jane Roe", target_type="person",
                            surfaces=["public"], started="now")
        inv.runs = [SourceRun("serper", "Serper", "public", "ok", results=[
            SearchResult("serper", "public", "Jane Roe",
                         snippet="Jane Roe on linkedin.com, github.com and "
                                 "wikidata.org")])]
        correlate(inv)
        vals = {e.value.lower() for e in inv.entities}
        for noisy in ("linkedin.com", "github.com", "wikidata.org"):
            self.assertNotIn(noisy, vals)

    def test_ai_flagged_extra_noise_drops_domain_and_subdomain(self):
        inv = Investigation(target="Jane Roe", target_type="person",
                            surfaces=["public"], started="now")
        inv.runs = [SourceRun("serper", "Serper", "public", "ok", results=[
            SearchResult("serper", "public", "Jane Roe",
                         snippet="Jane Roe seen on weirdcdn.io and "
                                 "es.weirdcdn.io")])]
        correlate(inv, extra_noise={"weirdcdn.io"})
        vals = {e.value.lower() for e in inv.entities}
        self.assertNotIn("weirdcdn.io", vals)
        self.assertNotIn("es.weirdcdn.io", vals)


class TestIndividualLinked(unittest.TestCase):
    """Fix C: only results about the person count as findings."""

    def _inv(self, results):
        inv = Investigation(target="Wong Jing Yi", target_type="person",
                            surfaces=["public"], started="now",
                            context="Ko Lui Secondary School")
        inv.runs = [SourceRun("serper", "Serper", "public", "ok",
                              results=results)]
        return inv

    def test_school_page_is_context_only(self):
        from blacknoir.agent import _individual_linked_results
        inv = self._inv([SearchResult("serper", "public",
                        "Ko Lui Secondary School",
                        snippet="a secondary school in Kwun Tong")])
        self.assertEqual(_individual_linked_results(inv), [])

    def test_named_page_and_breach_are_individual(self):
        from blacknoir.agent import _individual_linked_results
        named = SearchResult("serper", "public", "Wong Jing Yi blog",
                             snippet="posts by Wong Jing Yi")
        breach = SearchResult("hibp", "darkweb", "breach", snippet="pwned")
        school = SearchResult("serper", "public", "Ko Lui Secondary School",
                              snippet="a school")
        got = _individual_linked_results(self._inv([named, breach, school]))
        self.assertIn(named, got)
        self.assertIn(breach, got)
        self.assertNotIn(school, got)


class TestCandidateMerge(unittest.TestCase):
    """Fix D: same-person duplicates collapse to one candidate."""

    def _c(self, label, org="Ko Lui Secondary School", outcome="pending",
           score=1.0, n_ev=0):
        from blacknoir.deepsearch import Candidate
        c = Candidate(label=label, role="Student", org=org,
                      location="Hong Kong", context_match=score,
                      outcome=outcome)
        c.evidence = [SearchResult("s", "public", f"{label} {i}")
                      for i in range(n_ev)]
        return c

    def test_same_org_role_merge_keeps_best_outcome(self):
        from blacknoir.deepsearch import collapse_duplicate_candidates
        a = self._c("Wong Jing Yi (Ko Lui Secondary School Student)",
                    outcome="confirmed", n_ev=5)
        b = self._c("Wong Jing Yi (Hong Kong Student)", outcome="dry", n_ev=0)
        out = collapse_duplicate_candidates([a, b])
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].outcome, "confirmed")

    def test_excluded_candidate_never_merged(self):
        from blacknoir.deepsearch import collapse_duplicate_candidates
        a = self._c("A", outcome="confirmed", n_ev=3)
        b = self._c("B", outcome="excluded")
        self.assertEqual(len(collapse_duplicate_candidates([a, b])), 2)

    def test_distinct_orgs_do_not_merge(self):
        from blacknoir.deepsearch import collapse_duplicate_candidates
        a = self._c("Jess at PolyU", org="PolyU")
        b = self._c("Jess at HKUST", org="HKUST")
        self.assertEqual(len(collapse_duplicate_candidates([a, b])), 2)


class TestConstraintAndSelectionGate(unittest.TestCase):
    """Phase 4/5: per-candidate hard-constraint status and the human gate."""

    def _cand(self, label, role="", org="", loc="", score=0.0, ev_names=None):
        from blacknoir.deepsearch import Candidate
        c = Candidate(label=label, role=role, org=org, location=loc,
                      context_match=score)
        if ev_names:
            c.evidence = [SearchResult("s", "public", n, snippet=n)
                          for n in ev_names]
        return c

    def _state(self):
        from blacknoir.deepsearch import DeepSearchState
        return DeepSearchState(target="Wong Jing Yi",
                               context="Ko Lui Secondary School Hong Kong",
                               aliases=["王婧兒"])

    def test_higher_ed_namesake_contradicts(self):
        from blacknoir.deepsearch import constraint_status
        c = self._cand("WJY NUS", role="PhD Student", org="NUS",
                       loc="Singapore", score=0.05)
        self.assertEqual(constraint_status(c, self._state())[0], "contradicts")

    def test_named_in_context_supports(self):
        from blacknoir.deepsearch import constraint_status
        c = self._cand("WJY", org="Ko Lui Secondary School", score=0.9,
                       ev_names=["Wong Jing Yi at Ko Lui Secondary School"])
        self.assertEqual(constraint_status(c, self._state())[0], "supports")

    def test_context_only_is_unverified(self):
        from blacknoir.deepsearch import constraint_status
        c = self._cand("WJY school", org="Ko Lui Secondary School", score=1.0,
                       ev_names=["Ko Lui Secondary School page"])
        self.assertEqual(constraint_status(c, self._state())[0], "unverified")

    def test_no_constraint_is_unknown(self):
        from blacknoir.deepsearch import DeepSearchState, constraint_status
        c = self._cand("x", score=0.5)
        self.assertEqual(
            constraint_status(c, DeepSearchState(target="x", context=""))[0],
            "unknown")

    def test_gate_pursues_nothing_and_asks(self):
        from blacknoir.deepsearch import _present_for_selection
        st = self._state()
        st.candidates = [
            self._cand("A", org="Ko Lui Secondary School", score=1.0),
            self._cand("B", role="PhD", org="NUS", score=0.05)]
        _present_for_selection(st)
        # nothing pursued; every candidate carries a constraint tag; asks /focus
        self.assertTrue(all(c.outcome == "awaiting-selection"
                            for c in st.candidates))
        self.assertTrue(all("constraint" in c.attributes
                            for c in st.candidates))
        self.assertTrue(st.questions and "/focus" in st.questions[0])
        # the namesake is not silently given the target's school tag
        b = next(c for c in st.candidates if c.label == "B")
        self.assertEqual(b.attributes["constraint"], "contradicts")


if __name__ == "__main__":
    unittest.main(verbosity=2)
