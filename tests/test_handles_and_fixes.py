"""Offline regression tests for the identity-linking and reporting fixes.

No network, no API keys. Every network-touching path is driven by a fake
fetcher so the assertions are deterministic.

These exist because a false positive shipped once already: a profile declaring
only "Linus" was CONFIRMED as "Linus Torvalds" by substring matching, which
would have reported a stranger sharing a first name as an identity link. It was
caught by manual probing, not by reasoning — so the matching rules are pinned
here, adversarial cases first.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import blacknoir.deepsearch as ds
from blacknoir import handles as H
from blacknoir import http as bh
from blacknoir import report as rp
from blacknoir.config import get_source
from blacknoir.connectors import _looks_like_parser_break
from blacknoir.guardrails import Guardrails
from blacknoir.models import Investigation, SearchResult, SourceRun


class FakeFetcher:
    """Returns canned JSON per URL substring. Never touches the network."""

    def __init__(self, table=None, live=True):
        self.table = table or {}
        self.live = live
        self.calls = []

    def get_json(self, url, headers=None, timeout=None):
        self.calls.append(url)
        for frag, payload in self.table.items():
            if frag in url:
                return payload
        return {"__status__": 404}


def _gh(name):
    return {"login": "x", "name": name}


# --------------------------------------------------------------------------
# Name<->handle confirmation: the false-positive class
# --------------------------------------------------------------------------

class TestHandleConfirmation(unittest.TestCase):
    def _confirm(self, declared, target, aliases=None):
        f = FakeFetcher({"api.github.com/users/": _gh(declared)})
        return H.confirm_handle("someone", target, f, aliases)["verdict"]

    def test_exact_name_confirms(self):
        self.assertEqual(self._confirm("Linus Torvalds", "Linus Torvalds"),
                         "confirmed")

    def test_first_name_only_is_rejected(self):
        """The shipped bug: 'Linus' must NOT confirm 'Linus Torvalds'."""
        self.assertEqual(self._confirm("Linus", "Linus Torvalds"),
                         "unconfirmed")

    def test_name_fragment_is_rejected(self):
        self.assertEqual(self._confirm("Lin", "Linus Torvalds"), "unconfirmed")

    def test_surname_only_is_rejected(self):
        self.assertEqual(self._confirm("Torvalds", "Linus Torvalds"),
                         "unconfirmed")

    def test_similar_surname_is_rejected(self):
        """'Marshall' contains 'marsh' as a substring but is a different name."""
        self.assertEqual(self._confirm("Alex Marshall", "Alex Marsh"),
                         "unconfirmed")

    def test_superset_declaration_confirms(self):
        self.assertEqual(self._confirm("Dr Alex Marsh", "Alex Marsh"), "confirmed")

    def test_token_order_is_irrelevant(self):
        """Romanised CJK names invert surname/given order between platforms."""
        self.assertEqual(self._confirm("Jing Yi Wong", "Wong Jing Yi"),
                         "confirmed")

    def test_partial_cjk_name_is_rejected(self):
        self.assertEqual(self._confirm("Wong Jing", "Wong Jing Yi"),
                         "unconfirmed")

    def test_case_and_accents_normalised(self):
        self.assertEqual(self._confirm("JOSÉ GARCÍA", "Jose Garcia"),
                         "confirmed")

    def test_alias_can_confirm(self):
        self.assertEqual(self._confirm("王婧妍", "Wong Jing Yi", ["王婧妍"]),
                         "confirmed")

    def test_cjk_survives_normalisation(self):
        """An [^a-z0-9] filter erased CJK, silently killing native-script aliases."""
        self.assertEqual(H._norm("王婧妍"), "王婧妍")
        self.assertTrue(H._norm("王婧妍 Wong"))

    def test_cjk_name_does_not_match_a_different_cjk_name(self):
        self.assertEqual(self._confirm("李小明", "Wong Jing Yi", ["王婧妍"]),
                         "unconfirmed")

    def test_empty_target_never_confirms(self):
        """A name that normalises to nothing must not match everything."""
        self.assertEqual(self._confirm("Anybody At All", ""), "unconfirmed")

    def test_absent_account(self):
        f = FakeFetcher({})           # every lookup 404s
        self.assertEqual(H.confirm_handle("nope", "Jane Doe", f)["verdict"],
                         "absent")

    def test_account_with_no_declared_name_is_not_a_match(self):
        f = FakeFetcher({"api.github.com/users/": {"login": "x", "name": ""}})
        self.assertEqual(H.confirm_handle("x", "Jane Doe", f)["verdict"],
                         "absent")

    def test_plan_mode_makes_no_calls(self):
        f = FakeFetcher({"api.github.com/users/": _gh("Jane Doe")}, live=False)
        run = H.link_name_to_handles("Jane Doe", ["janedoe"], f)
        self.assertEqual(run.status, "planned")
        self.assertEqual(f.calls, [])

    def test_unconfirmed_is_reported_as_not_linked(self):
        """A same-handle stranger must be surfaced, and never as a link."""
        f = FakeFetcher({"api.github.com/users/": _gh("Maciej Jarczok")})
        run = H.link_name_to_handles("Alex Marsh", ["amarsh"], f)
        verdicts = [(r.meta or {}).get("verdict") for r in run.results]
        self.assertIn("unconfirmed", verdicts)
        self.assertNotIn("confirmed", verdicts)
        self.assertIn("NOT LINKED", run.results[0].snippet)


# --------------------------------------------------------------------------
# Handle generation
# --------------------------------------------------------------------------

class TestHandleGeneration(unittest.TestCase):
    def test_two_token_name(self):
        out = H.handle_permutations("Alex Marsh")
        for want in ("alexmarsh", "amarsh", "marshalex"):
            self.assertIn(want, out)

    def test_three_token_name_keeps_middle(self):
        """'Wong Jing Yi' must not collapse to 'wongyi'."""
        out = H.handle_permutations("Wong Jing Yi")
        self.assertIn("wongjingyi", out)
        self.assertIn("jingyiwong", out)

    def test_three_token_strong_forms_lead(self):
        """Caller caps the list, so full concatenations must not be at the tail."""
        out = H.handle_permutations("Wong Jing Yi")
        self.assertLess(out.index("wongjingyi"), 4)

    def test_single_token_name(self):
        self.assertEqual(H.handle_permutations("Madonna"), ["madonna"])

    def test_contextual_suffix_shape(self):
        """The AMarsh-Sec case: field-suffixed handles must be generated."""
        out = H.contextual_handles("Alex Marsh", "AI security researcher")
        self.assertIn("amarsh-security", out)
        self.assertIn("amarsh-ai", out)

    def test_contextual_uses_affiliation_initialism(self):
        out = H.contextual_handles("Wong Jing Yi", "Ko Lui Secondary School")
        self.assertTrue(any("kls" in h for h in out))

    def test_contextual_drops_generic_words(self):
        out = H.contextual_handles("Jane Doe", "secondary school student")
        self.assertFalse(any("secondary" in h or "student" in h for h in out))

    def test_generated_handles_are_length_legal(self):
        for name, ctx in (("Alex Marsh", "AI security"),
                          ("Wong Jing Yi", "Ko Lui Secondary School")):
            for h in H.contextual_handles(name, ctx) + H.handle_permutations(name):
                self.assertTrue(2 <= len(h) <= 39, h)

    def test_cjk_names_generate_no_handles(self):
        """CJK compares fine as a NAME but is never a valid platform handle."""
        self.assertEqual(H.handle_permutations("王婧妍"), [])
        for h in H.contextual_handles("Wong Jing Yi", "香港 高蕾中學"):
            self.assertTrue(h.isascii(), h)


class TestHandleHarvest(unittest.TestCase):
    def _urls(self, *urls):
        return [SearchResult("s", "public", title="t", url=u) for u in urls]

    def test_extracts_profile_handles(self):
        out = H.handles_from_results(self._urls(
            "https://github.com/AMarsh-Sec",
            "https://www.linkedin.com/in/amarsh87"))
        self.assertIn("amarsh-sec", out)
        self.assertIn("amarsh87", out)

    def test_site_furniture_excluded(self):
        out = H.handles_from_results(self._urls(
            "https://github.com/features/copilot",
            "https://instagram.com/explore/tags",
            "https://github.com/enterprise"))
        self.assertEqual(out, [])

    def test_locale_segments_excluded(self):
        """github.com/en is a real account (Julian Sun), not our target."""
        out = H.handles_from_results(self._urls("https://github.com/en",
                                                "https://github.com/zh"))
        self.assertEqual(out, [])

    def test_most_seen_handle_ranks_first(self):
        out = H.handles_from_results(self._urls(
            "https://github.com/alpha", "https://github.com/beta",
            "https://github.com/beta/repo", "https://github.com/beta/other"))
        self.assertEqual(out[0], "beta")


# --------------------------------------------------------------------------
# Dork verification
# --------------------------------------------------------------------------

class TestContextNoiseGate(unittest.TestCase):
    """Pages that mention the SCHOOL but never the person.

    A context-qualified query ("<name> <school>") makes the engine return pages
    about the school, so directory and listing pages arrive in bulk. They may
    appear under their source for auditability, but they must never qualify as
    being about the individual.
    """

    T = "Wong Jing Yi"
    CTX = "+852 5550 0100 高蕾中學 Hong Kong"
    AL = ["王婧妍"]

    def _about(self, text):
        from blacknoir.entities import is_about_target
        return is_about_target(text, self.T, self.CTX, self.AL)

    def test_cjk_context_is_tokenised(self):
        """[a-z0-9]+ tokenised 高蕾中學 to nothing, dropping the best signal."""
        from blacknoir.entities import _significant_tokens
        self.assertIn("高蕾中學", _significant_tokens(self.CTX))

    def test_school_directory_page_is_not_about_the_person(self):
        self.assertFalse(self._about(
            "中學概覽 School Profile 高蕾中學 Ko Lui Secondary School "
            "chsc.hk/ssp2025/sch_detail.php"))

    def test_government_school_list_is_not_about_the_person(self):
        self.assertFalse(self._about(
            "觀塘 KWUN TONG 高蕾中學 九龍 電話 23890213 school-list-kt"))

    def test_inter_school_event_listing_is_not_about_the_person(self):
        self.assertFalse(self._about(
            "mysmartabc.com/drama2025/ 中學組 參賽學校 高蕾中學 戲劇比賽"))

    def test_page_naming_her_still_qualifies(self):
        self.assertTrue(self._about("中二級家長晚會 王婧妍 2A 高蕾中學"))
        self.assertTrue(self._about("Wong Jing Yi 高蕾中學 robotics"))

    def test_short_syllable_does_not_substring_match(self):
        """'yi' is inside 'Yiu'/'Ying'; raw substring matching accepted both."""
        self.assertFalse(self._about("Chan Yiu Ming 高蕾中學 teacher list"))
        self.assertFalse(self._about("Lee Ying Wah 高蕾中學 prize list"))

    def test_western_surname_plus_context_still_qualifies(self):
        from blacknoir.entities import is_about_target
        self.assertTrue(is_about_target(
            "Marsh presenting AI security research", "Alex Marsh", "AI security"))

    def test_shared_first_name_still_rejected(self):
        from blacknoir.entities import is_about_target
        self.assertFalse(is_about_target(
            "Ep. 156: AI Security w/ Alex Bell", "Alex Marsh", "AI security"))

    def test_bare_common_surname_is_not_enough(self):
        self.assertFalse(self._about("Wong 高蕾中學 alumni page"))

    def test_context_only_evidence_does_not_grade_a_candidate(self):
        """Two school pages and no named page must not reach 'confirmed'."""
        st = ds.DeepSearchState(target=self.T, context=self.CTX)
        st.aliases = self.AL
        c = ds.Candidate(label="c", context_match=0.95)
        c.evidence = [
            SearchResult("s", "public", title="高蕾中學 School Profile",
                         url="https://chsc.hk/x", snippet="Ko Lui Secondary"),
            SearchResult("s", "public", title="觀塘 school list",
                         url="https://edb.gov.hk/y", snippet="高蕾中學 23890213"),
        ]
        self.assertNotEqual(ds._grade(c, st, min_evidence=2), "confirmed")


class TestDorkHonouring(unittest.TestCase):
    def _r(self, *urls):
        return [SearchResult("s", "public", title="t", url=u) for u in urls]

    def test_site_operator_obeyed(self):
        self.assertTrue(ds._dork_was_honoured(
            'site:linkedin.com/in "X"',
            self._r("https://www.linkedin.com/in/someone")))

    def test_site_operator_ignored(self):
        """A free SERP plan strips the operator and answers a different query."""
        self.assertFalse(ds._dork_was_honoured(
            'site:linkedin.com/in "X"',
            self._r("https://en.wikipedia.org/wiki/X",
                    "https://forbes.com/profile/x")))

    def test_filetype_operator_obeyed(self):
        self.assertTrue(ds._dork_was_honoured(
            'filetype:pdf "X"', self._r("https://school.edu/roster.pdf")))

    def test_filetype_operator_ignored(self):
        self.assertFalse(ds._dork_was_honoured(
            'filetype:pdf "X"', self._r("https://en.wikipedia.org/wiki/X")))

    def test_empty_results_not_honoured(self):
        self.assertFalse(ds._dork_was_honoured('site:x.com "X"', []))

    def test_non_dork_query(self):
        self.assertFalse(ds._dork_was_honoured(
            "plain query", self._r("https://a.com")))

    def test_dork_budget_splits_across_categories(self):
        """Platform dorks must not starve the filetype dorks (or vice versa)."""
        qs = ds._wall_dorks("Jane Doe", "", "person", limit=6)
        self.assertTrue(any(q.startswith("site:") for q in qs))
        self.assertTrue(any(q.startswith("filetype:") for q in qs))

    def test_infra_target_gets_no_social_dorks(self):
        qs = ds._wall_dorks("example.com", "", "domain")
        self.assertFalse(any(q.startswith("site:") for q in qs))

    def test_dorks_keep_their_operators(self):
        """sanitize_query would strip these; the dork path must not apply it."""
        from blacknoir.config import has_advanced_operators
        for q in ds._wall_dorks("Jane Doe", "", "person"):
            self.assertTrue(has_advanced_operators(q), q)


# --------------------------------------------------------------------------
# Recon queries
# --------------------------------------------------------------------------

class TestReconQueries(unittest.TestCase):
    def test_person_target_gets_a_platform_query(self):
        """'Alex Marsh github' finds AMarsh-Sec; 'Alex Marsh' finds the wrong one."""
        qs = ds._recon_queries("Alex Marsh", "AI security", "person")
        self.assertTrue(any("github" in q.lower() for q in qs))

    def test_username_target_leads_with_github(self):
        qs = ds._recon_queries("nightowl", "", "username")
        self.assertTrue(any("github" in q.lower() for q in qs))

    def test_recon_queries_are_operator_free(self):
        from blacknoir.config import has_advanced_operators
        for q in ds._recon_queries("Jane Doe", "Acme Corp", "person"):
            self.assertFalse(has_advanced_operators(q), q)


# --------------------------------------------------------------------------
# Candidate grading (the original false-negative bug)
# --------------------------------------------------------------------------

class TestCandidateGrading(unittest.TestCase):
    def _cand(self, n_evidence, name="Wong Jing Yi"):
        c = ds.Candidate(label="c", context_match=0.95)
        c.evidence = [
            SearchResult("s", "public", title=f"{name} page {i}",
                         url=f"https://x{i}.com", snippet=name)
            for i in range(n_evidence)]
        return c

    def test_evidence_backed_candidate_is_confirmed(self):
        """A dry exit used to discard evidence and stamp 'dry' without grading."""
        st = ds.DeepSearchState(target="Wong Jing Yi", context="KLSS")
        self.assertEqual(ds._grade(self._cand(2), st, min_evidence=2),
                         "confirmed")

    def test_no_evidence_is_dry(self):
        st = ds.DeepSearchState(target="Wong Jing Yi", context="KLSS")
        self.assertEqual(ds._grade(self._cand(0), st, min_evidence=2), "dry")

    def test_dry_is_never_hardcoded_in_deep_dive(self):
        import inspect
        src = inspect.getsource(ds.deep_dive)
        self.assertNotIn('cand.outcome = "dry"', src)

    def test_confirmed_string_is_never_the_only_resolution_check(self):
        self.assertIn("operator-confirmed", ds.RESOLVED_OUTCOMES)
        self.assertIn("confirmed", ds.RESOLVED_OUTCOMES)

    def test_operator_confirmation_outranks_inferred(self):
        self.assertEqual(
            ds._better_outcome("operator-confirmed", "confirmed"),
            "operator-confirmed")


# --------------------------------------------------------------------------
# Report honesty
# --------------------------------------------------------------------------

class TestReportCounts(unittest.TestCase):
    def _inv(self):
        inv = Investigation(target="X", target_type="person",
                            surfaces=["public"], started="now")
        inv.runs = [
            SourceRun("ahmia", "Ahmia", "darkweb", "empty"),
            SourceRun("deepsearch_serper", "Serper", "public", "ok"),
            SourceRun("deepsearch_bing", "Bing", "public", "blocked"),
            SourceRun("deepsearch_recon", "recon", "public", "skipped"),
            SourceRun("deepsearch_candidate_1", "Cand 1", "public", "ok"),
            SourceRun("deepsearch_candidate_2", "Cand 2", "public", "ok"),
        ]
        return inv

    def test_candidates_are_not_counted_as_sources(self):
        real = rp._real_source_runs(self._inv())
        self.assertEqual(len(real), 3)

    def test_synthetic_rows_detected(self):
        for key in ("deepsearch_candidate_1", "deepsearch_recon"):
            self.assertTrue(rp._is_synthetic_run(
                SourceRun(key, "l", "public", "ok")))
        self.assertFalse(rp._is_synthetic_run(
            SourceRun("deepsearch_serper", "l", "public", "ok")))

    def test_stat_cards_report_real_counts(self):
        cards = rp._stat_cards(self._inv())
        self.assertIn(">3<", cards)          # 3 sources queried, not 6
        self.assertNotIn(">6<", cards)

    def test_candidate_rows_sort_after_engines(self):
        inv = self._inv()
        html = rp._runs_table(inv)
        self.assertLess(html.index("Serper"), html.index("Cand 1"))
        self.assertIn("Identity candidates", html)

    def test_ruled_out_namesake_evidence_is_withheld(self):
        inv = Investigation(target="X", target_type="person",
                            surfaces=["public"], started="now")
        inv.deep_search = {"candidates": [{
            "label": "Namesake", "outcome": "excluded", "context_match": 0.0,
            "evidence": [{"title": "t", "url": "https://linkedin.com/in/PRIVATE"}],
        }]}
        html = rp._candidates_html(inv)
        self.assertNotIn("PRIVATE", html)
        self.assertIn("Namesakes ruled out", html)


# --------------------------------------------------------------------------
# Parser-break detection
# --------------------------------------------------------------------------

class TestParserBreak(unittest.TestCase):
    def setUp(self):
        self.ddg = get_source("duckduckgo")
        self.populated = "<html>" + "".join(
            f'<div><a href="https://s{i}.com/x">R{i}</a>'
            f'<p>{"filler " * 20}</p></div>' for i in range(30)) + "</html>"

    def test_populated_page_with_no_parse_is_a_break(self):
        self.assertTrue(_looks_like_parser_break(self.populated, self.ddg, []))

    def test_engine_saying_no_results_is_believed(self):
        body = ("<html>Your search did not match any documents."
                + "pad " * 500 + "</html>")
        self.assertFalse(_looks_like_parser_break(body, self.ddg, []))

    def test_short_body_is_not_a_break(self):
        self.assertFalse(_looks_like_parser_break("<html>err</html>",
                                                  self.ddg, []))

    def test_results_found_is_not_a_break(self):
        self.assertFalse(_looks_like_parser_break(self.populated, self.ddg,
                                                  ["r"]))

    def test_generic_parser_sources_are_exempt(self):
        """No dedicated selector means nothing to go stale."""
        self.assertFalse(_looks_like_parser_break(
            self.populated, get_source("ahmia"), []))


# --------------------------------------------------------------------------
# Transport
# --------------------------------------------------------------------------

class TestTransport(unittest.TestCase):
    def tearDown(self):
        import os
        os.environ.pop("BLACKNOIR_IMPERSONATE", None)

    def _set(self, val):
        import os
        os.environ["BLACKNOIR_IMPERSONATE"] = val

    def test_honest_by_default(self):
        self.assertEqual(bh.impersonation_target(), "")
        self.assertIn("honest", bh.transport_status())

    def test_off_values(self):
        for v in ("off", "0", "false", "no", "none", ""):
            self._set(v)
            self.assertEqual(bh.impersonation_target(), "")

    def test_on_maps_to_chrome(self):
        self._set("on")
        self.assertEqual(bh.impersonation_target(), "chrome")

    def test_invalid_target_falls_back_and_says_so(self):
        """curl_cffi validates lazily; a typo must not break every request."""
        self._set("bogus-browser-9000")
        status = bh.transport_status()
        if bh._HAS_CURL_CFFI:
            self.assertIn("not a target", status)
            sess = bh.Fetcher(Guardrails(), live=True)._session
            self.assertNotIn("curl_cffi", type(sess).__module__)

    def test_honest_session_keeps_blacknoir_ua(self):
        sess = bh.Fetcher(Guardrails(), live=True)._session
        self.assertIn("BlackNoir", sess.headers.get("User-Agent", ""))


class TestOperatorFetch(unittest.TestCase):
    """/fetch reads one operator-named page. It must not become an SSRF hole."""

    INTERNAL = [
        "http://localhost:8080/admin", "http://127.0.0.1/",
        "http://169.254.169.254/latest/meta-data/", "http://10.0.0.5/x",
        "http://192.168.1.1/", "http://172.16.0.1/", "http://[::1]/",
        "http://router.local/", "http://metadata.google.internal/",
    ]

    def test_operator_authorisation_allows_an_ordinary_host(self):
        g = Guardrails()
        url = "https://www.mysmartabc.com/drama2025/"
        self.assertFalse(g.can_fetch(url)[0])       # not on the curated list
        g.authorize_host(url)
        self.assertTrue(g.can_fetch(url)[0])        # operator named it

    def test_internal_addresses_refused_even_when_authorised(self):
        for u in self.INTERNAL:
            g = Guardrails()
            g.authorize_host(u)
            ok, why = g.can_fetch(u)
            self.assertFalse(ok, f"{u} was allowed ({why})")
            self.assertIn("internal-address-blocked", why)

    def test_onion_and_downloads_refused_even_when_authorised(self):
        for u, frag in (("http://abcdefghij234567.onion/x", "onion"),
                        ("https://example.com/p.exe", "download-blocked"),
                        ("file:///C:/Windows/win.ini", "scheme-not-allowed")):
            g = Guardrails()
            g.authorize_host(u)
            ok, why = g.can_fetch(u)
            self.assertFalse(ok, u)
            self.assertIn(frag, why)

    def test_authorisation_is_audited(self):
        g = Guardrails()
        g.authorize_host("https://example.org/page")
        self.assertTrue(any(e.action == "authorize" for e in g.events))

    def test_plan_mode_fetches_nothing(self):
        from blacknoir.webfetch import fetch_page

        class Dead:
            live = False
            guard = Guardrails()

            def probe(self, *a, **k):
                raise AssertionError("network touched in plan mode")

        out = fetch_page("https://example.com/", Dead())
        self.assertFalse(out["ok"])
        self.assertIn("plan-only", out["note"])

    def test_script_and_style_are_not_content(self):
        from blacknoir.webfetch import _strip_dead_weight
        html = ("<html><head><style>body{font-family:Calibri;color:#fff}</style>"
                "<script>var x=1;alert(2)</script></head>"
                "<body><p>Real content here</p></body></html>")
        out = _strip_dead_weight(html)
        self.assertNotIn("Calibri", out)
        self.assertNotIn("alert", out)
        self.assertIn("Real content here", out)

    def test_title_is_extracted(self):
        from blacknoir.webfetch import _title
        self.assertEqual(
            _title("<html><head><title>  Drama  Competition </title></head>"),
            "Drama Competition")


class TestReflectionTrigger(unittest.TestCase):
    """When should the loop decide its own sweep failed and re-query?

    The first version asked "did anything name the target?" and a namesake
    always satisfies that. Measured on a real run: a sweep returned a
    University of London namesake plus ten pages about the right school, and
    not one page that was both — so the reflection never fired on exactly the
    case it exists for.
    """

    def _state(self, context="高雷中學 Hong Kong"):
        st = ds.DeepSearchState(target="Wong Jing Yi", context=context)
        st.aliases = ["王婧兒"]
        return st

    def _r(self, title, url="https://x.test/p", snippet=""):
        return SearchResult("s", "public", title=title, url=url,
                            snippet=snippet)

    def test_namesake_alone_does_not_count_as_found(self):
        namesake = self._r("Wong Jing Yi - Student at University of London",
                           "https://sg.linkedin.com/in/wong-jing-yi-a89266137")
        self.assertFalse(ds._names_target_in_context(namesake, self._state()))

    def test_school_page_alone_does_not_count_as_found(self):
        school = self._r("高雷中學 Ko Lui Secondary School",
                         "https://www.klss.edu.hk/")
        self.assertFalse(ds._names_target_in_context(school, self._state()))

    def test_name_plus_context_counts_as_found(self):
        hit = self._r("高雷中學 - Achievement",
                      "https://www.klss.edu.hk/achievement",
                      snippet="Wong Jing Yi 中二級")
        self.assertTrue(ds._names_target_in_context(hit, self._state()))

    def test_alias_plus_context_counts_as_found(self):
        hit = self._r("中二級家長晚會 王婧兒 高雷中學",
                      "https://www.klss.edu.hk/x")
        self.assertTrue(ds._names_target_in_context(hit, self._state()))

    def test_without_context_naming_is_enough(self):
        namesake = self._r("Wong Jing Yi - University of London")
        self.assertTrue(ds._names_target_in_context(namesake,
                                                    self._state(context="")))

    def test_heuristic_reflection_targets_observed_domains(self):
        """Model-free path: turn the domains the results revealed into queries."""
        st = self._state()
        results = [self._r("高雷中學", "https://www.klss.edu.hk/"),
                   self._r("觀塘", "https://www.edb.gov.hk/x")]
        qs = ds._heuristic_reflection(st, results)
        self.assertIn('site:klss.edu.hk "Wong Jing Yi"', qs)
        self.assertTrue(any("王婧兒" in q for q in qs),
                        "native-script alias never tried on its own")


class TestOrgVsPersonBalance(unittest.TestCase):
    """A sweep dominated by the organisation looks productive and is not."""

    def _state(self):
        st = ds.DeepSearchState(target="Wong Jing Yi",
                                context="高雷中學 Hong Kong")
        st.aliases = ["王婧兒"]
        return st

    def _r(self, title, url="https://x.test/p", snippet=""):
        return SearchResult("s", "public", title=title, url=url,
                            snippet=snippet)

    def test_counts_person_vs_context_only(self):
        results = [
            self._r("高雷中學 Ko Lui Secondary School", "https://klss.edu.hk/"),
            self._r("高雷中學 - 維基百科", "https://zh.wikipedia.org/x"),
            self._r("高雷中學 Achievement", "https://klss.edu.hk/achievement",
                    snippet="Wong Jing Yi 中二級"),
        ]
        person, ctx_only = ds.org_vs_person(results, self._state())
        self.assertEqual((person, ctx_only), (1, 2))

    def test_alias_goes_out_unqualified(self):
        """The org must not be appended to every single query."""
        qs = ds._recon_queries("Wong Jing Yi", "高雷中學 Hong Kong", "person",
                               None, ["王婧兒"])
        self.assertIn("王婧兒", qs)

    def test_broadening_probes_survive_the_alias(self):
        qs = ds._recon_queries("Wong Jing Yi", "高雷中學 Hong Kong", "person",
                               None, ["王婧兒"])
        self.assertTrue(any("github" in q.lower() for q in qs))
        self.assertTrue(any("linkedin" in q.lower() for q in qs))


class TestPhoneStructure(unittest.TestCase):
    """Keyless numbering-plan analysis. Must never name a subscriber."""

    def test_hk_mobile_identified(self):
        from blacknoir.phone import analyse
        a = analyse("+852 5550 0100")
        self.assertEqual(a["country"], "Hong Kong")
        self.assertIn("mobile", a["line_type"])

    def test_carrier_is_explicitly_not_determinable(self):
        """Portability since 1999 — the prefix says nothing about the operator."""
        from blacknoir.phone import analyse
        self.assertEqual(analyse("+852 5550 0100")["carrier"],
                         "not determinable")

    def test_hk_line_types(self):
        from blacknoir.phone import analyse
        for lead, expect in (("2", "fixed"), ("3", "fixed"), ("5", "mobile"),
                             ("6", "mobile"), ("9", "mobile")):
            self.assertIn(expect, analyse(f"+852 {lead}5500100")["line_type"])

    def test_missing_plus_accepted_when_length_is_unambiguous(self):
        from blacknoir.phone import normalise
        self.assertEqual(normalise("852-5550-0100"), ("852", "55500100"))

    def test_ambiguous_bare_digits_are_not_guessed(self):
        from blacknoir.phone import normalise
        cc, _ = normalise("55500100")           # no country code at all
        self.assertEqual(cc, "")

    def test_wrong_length_is_flagged_not_silently_accepted(self):
        from blacknoir.phone import analyse
        notes = " ".join(analyse("+852 12345")["notes"]).lower()
        self.assertIn("8 digits", notes)

    def test_never_claims_to_identify_the_holder(self):
        from blacknoir.phone import run_phone
        blob = " ".join(f"{r.title} {r.snippet}"
                        for r in run_phone("+852 5550 0100").results).lower()
        for phrase in ("owner is", "belongs to", "registered to",
                       "subscriber name"):
            self.assertNotIn(phrase, blob)

    def test_runs_without_network_or_key(self):
        """The whole point: a phone target used to yield nothing without a key."""
        from blacknoir.phone import run_phone
        run = run_phone("+852 5550 0100")
        self.assertEqual(run.status, "ok")
        self.assertTrue(run.results)


class TestPwnedPasswordsGuardrail(unittest.TestCase):
    def test_range_api_host_allowlisted(self):
        ok, _ = Guardrails().can_fetch(
            "https://api.pwnedpasswords.com/range/21BD1")
        self.assertTrue(ok)

    def test_lookalike_host_refused(self):
        ok, _ = Guardrails().can_fetch(
            "https://api.pwnedpasswords.com.evil.test/range/21BD1")
        self.assertFalse(ok)

    def test_plan_mode_sends_nothing(self):
        from blacknoir.selfaudit import check_password_pwned
        f = FakeFetcher({}, live=False)
        out = check_password_pwned("hunter2", f)
        self.assertEqual(out["status"], "planned")
        self.assertEqual(f.calls, [])


class TestTargetTypeRouting(unittest.TestCase):
    """A model-declared type that the pipeline cannot route disables every
    type-keyed module silently. Observed: 'other' for a phone number meant the
    numbering-plan analysis, phone pivots and Numverify all declined a target
    the deterministic classifier types without hesitation."""

    def test_unroutable_declared_type_falls_back_to_the_classifier(self):
        from blacknoir.entities import resolve_target_type
        self.assertEqual(
            resolve_target_type("other", "+852 5550 0101"), "phone")

    def test_declared_type_wins_when_the_pipeline_can_route_it(self):
        from blacknoir.entities import resolve_target_type
        # 'person' and 'name' are both routable and mean different things to
        # the person gate, so the model's choice is not second-guessed.
        self.assertEqual(
            resolve_target_type("person", "Lam Wing Kit"), "person")

    def test_every_routable_type_survives_the_round_trip(self):
        from blacknoir.entities import KNOWN_TARGET_TYPES, resolve_target_type
        for t in KNOWN_TARGET_TYPES:
            self.assertEqual(resolve_target_type(t, "whatever"), t)

    def test_parse_target_schema_offers_no_unroutable_type(self):
        """The schema is the source of the bad value: it advertised 'other' as
        a legal answer, so the model supplying it was following instructions."""
        import inspect

        from blacknoir.agent import Agent
        src = inspect.getsource(Agent.parse_target)
        self.assertNotIn('|other"', src)
        self.assertIn("phone", src)


class TestSourceApplicability(unittest.TestCase):
    """`good_for` describes what a source indexes, so it binds the model's pick
    as much as the heuristic's."""

    def test_code_search_dropped_for_a_person_target(self):
        from blacknoir.agent import _applicable
        from blacknoir.config import REGISTRY
        self.assertFalse(_applicable(REGISTRY["github"], "person"))
        self.assertFalse(_applicable(REGISTRY["github"], "name"))

    def test_code_search_kept_for_a_username_target(self):
        from blacknoir.agent import _applicable
        from blacknoir.config import REGISTRY
        self.assertTrue(_applicable(REGISTRY["github"], "username"))

    def test_unknown_type_drops_nothing(self):
        from blacknoir.agent import _applicable
        from blacknoir.config import REGISTRY
        self.assertTrue(_applicable(REGISTRY["github"], ""))

    def test_merge_plans_drops_an_inapplicable_pick(self):
        from blacknoir.agent import Agent
        from blacknoir.config import REGISTRY
        a = Agent(use_llm=False)

        class _Inv:
            target = "Lam Wing Kit"
            target_type = "person"

        plans = [{"selected": [{"key": "serper", "why": "a"},
                               {"key": "github", "why": "b"}],
                  "queries": ["q1"]}]
        merged = a._merge_plans(plans, list(REGISTRY.values()), _Inv())
        keys = [s["key"] for s in merged["selected"]]
        self.assertIn("serper", keys)
        self.assertNotIn("github", keys)
        self.assertIn("cannot key", merged["reasoning"])

    def test_connector_declines_a_bare_phrase_and_says_why(self):
        """The junk that poisoned handle confirmation: 'Lam Wing Kit' matched a
        dozen NEWS changelogs because each token occurs in release notes."""
        from blacknoir.connectors import _run_github
        run = _run_github(get_source("github"), "Lam Wing Kit",
                          FakeFetcher({}, live=True))
        self.assertEqual(run.status, "skipped")
        self.assertIn("identifier", run.detail)
        self.assertEqual(run.results, [])

    def test_connector_accepts_identifier_shaped_queries(self):
        from blacknoir.connectors import _is_code_identifier
        for q in ("nightowl", "amarsh-sec", "a@b.com", "example.com"):
            self.assertTrue(_is_code_identifier(q), q)
        for q in ("Lam Wing Kit", "+852 5550 0101", "Ada Lovelace"):
            self.assertFalse(_is_code_identifier(q), q)


class TestNoTraceClaimGuard(unittest.TestCase):
    """'No personal data traces were found' is read as "you are clean" and acted
    on, so it may only stand when the evidence list is genuinely empty. A run
    once emitted it while its own candidate held a school page naming the
    target."""

    def test_claim_stripped_when_results_name_the_target(self):
        from blacknoir.agent import _guard_no_trace_claim
        out = _guard_no_trace_claim(
            ["No personal data traces were found for this individual - "
             "nothing exposed to remediate."],
            [SearchResult("serper", "public", title="Achievements",
                          snippet="Lam Wing Kit 4B")])
        self.assertTrue(out)
        joined = " ".join(out).lower()
        self.assertNotIn("no personal data traces", joined)
        self.assertIn("carry the target's name", joined)

    def test_claim_kept_when_there_is_genuinely_nothing(self):
        from blacknoir.agent import _guard_no_trace_claim
        claim = ["No personal data traces were found for this individual - "
                 "nothing exposed to remediate."]
        self.assertEqual(_guard_no_trace_claim(claim, []), claim)

    def test_real_findings_are_never_dropped(self):
        from blacknoir.agent import _guard_no_trace_claim
        out = _guard_no_trace_claim(
            ["Breach record in Collection #1.",
             "Nothing exposed to remediate."],
            [SearchResult("hibp", "darkweb", title="x", snippet="y")])
        self.assertIn("Breach record in Collection #1.", out)


class TestPhoneEntityHygiene(unittest.TestCase):
    """Phone nodes assert that a number is connected to a person, so a parse
    artifact here is a claim about a real line."""

    def _inv(self, title, snippet, url):
        inv = Investigation(target="Lam Wing Kit", target_type="person",
                            surfaces=["public"], started="now")
        inv.runs.append(SourceRun(
            "serper", "Serper", "public", "ok",
            results=[SearchResult("serper", "public", title=title,
                                  snippet=snippet, url=url)]))
        return inv

    def test_url_path_fragment_is_not_a_phone(self):
        """`/c186330-40010797.html` (a people.com.cn article id) passed every
        length and formatting check and became a 'phone' wired to the target."""
        from blacknoir.entities import correlate
        inv = self._inv("Lam Wing Kit", "Lam Wing Kit profile",
                        "http://jx.people.com.cn/n2/2022/c186330-40010797.html")
        correlate(inv)
        self.assertEqual([e.value for e in inv.entities if e.kind == "phone"],
                         [])

    def test_same_line_two_ways_collapses_to_one_node(self):
        from blacknoir.entities import correlate
        inv = self._inv("Lam Wing Kit",
                        "Lam Wing Kit - tel (852) 5550 0102 / 5550 0102", "")
        correlate(inv)
        phones = [e.value for e in inv.entities if e.kind == "phone"]
        self.assertEqual(len(phones), 1, phones)
        # the fuller form is the one kept, and its brackets are balanced
        self.assertIn("852", phones[0])
        self.assertEqual(phones[0].count("("), phones[0].count(")"))

    def test_unbalanced_bracket_value_is_refused(self):
        from blacknoir.entities import correlate
        inv = self._inv("Lam Wing Kit", "Lam Wing Kit 852) 5550 0102", "")
        correlate(inv)
        for e in inv.entities:
            if e.kind == "phone":
                self.assertEqual(e.value.count("("), e.value.count(")"))

    def test_a_genuine_number_still_forms_a_node(self):
        """The guards must not be so tight that nothing survives them."""
        from blacknoir.entities import correlate
        inv = self._inv("Lam Wing Kit", "Contact Lam Wing Kit on +852 5550 0103",
                        "")
        correlate(inv)
        phones = [e.value for e in inv.entities if e.kind == "phone"]
        self.assertEqual(len(phones), 1, phones)
        self.assertIn("5550 0103", phones[0])


if __name__ == "__main__":
    unittest.main()
