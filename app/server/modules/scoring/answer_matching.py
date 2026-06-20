"""
Answer normalization & matching for the scoreboard.

The scoreboard historically compared answers with a bare ``strip().lower()`` plus
``;``-separated alternates. That marks structurally-identical indicators wrong:
``http://bad-domain.com``, ``bad-domain.com`` and ``bad-domain.com/`` would all score
differently, and threat analysts habitually *defang* indicators
(``hxxp://bad-domain[.]com``, ``user[at]evil.com``, ``1[.]2[.]3[.]4``).

This module canonicalizes BOTH the submitted value and each accepted answer through
the same function before comparing. Because the same transformation is applied to
both sides, normalization can only ever *add* matches — it can never reject an answer
that the old exact-match logic accepted. So it is backward-compatible by construction.

Dependency-free (stdlib only), so it is safe to import anywhere, including early in
``models.py``.

Care is taken NOT to rewrite lone backslashes, drive letters, or paths, so answers
like ``HKCU\\Software\\...\\Run`` or ``C:\\Windows\\Temp\\x.exe`` (common for the
persistence / lateral-movement techniques) are left intact.
"""

# Literal defang -> refang token replacements, applied in order on a lowercased string.
# Multi-character tokens come before their shorter substrings (e.g. hxxps before hxxp).
_REFANG_TOKENS = (
    ("hxxps://", "https://"),
    ("hxxp://", "http://"),
    ("hxxps", "https"),
    ("hxxp", "http"),
    ("meow://", "http://"),     # some sandboxes rewrite scheme to meow://
    ("[://]", "://"),
    ("[:]", ":"),
    ("[.]", "."),
    ("(.)", "."),
    ("{.}", "."),
    ("[dot]", "."),
    ("(dot)", "."),
    ("[d0t]", "."),
    (" [dot] ", "."),
    ("[at]", "@"),
    ("(at)", "@"),
    ("[@]", "@"),
)

# URL schemes stripped so "http://host/x" and "host/x" compare equal
_SCHEMES = ("https://", "http://", "ftps://", "ftp://")


def refang(value: str) -> str:
    """Convert common defanged indicator notation back to its real form."""
    s = value
    for token, replacement in _REFANG_TOKENS:
        if token in s:
            s = s.replace(token, replacement)
    return s


def normalize_answer(value, answer_type: str = None) -> str:
    """
    Canonicalize an answer/indicator for comparison.

    Steps (all symmetric, so applied identically to submitted and accepted values):
      1. coerce to string, trim, lowercase
      2. refang analyst notation
      3. strip wrapping angle brackets  <...>
      4. strip a leading URL scheme (http://, https://, ftp://, ftps://)
      5. strip trailing slashes
      6. collapse internal whitespace runs to a single space

    ``answer_type`` is accepted for forward-compatibility with per-type normalizers;
    the current implementation treats everything with the same conservative ruleset.
    """
    if value is None:
        return ""
    s = str(value).strip().lower()
    if not s:
        return ""

    s = refang(s)

    # strip wrapping angle brackets, e.g. <http://bad.com>
    while len(s) >= 2 and s[0] == "<" and s[-1] == ">":
        s = s[1:-1].strip()

    # strip a single leading URL scheme
    for scheme in _SCHEMES:
        if s.startswith(scheme):
            s = s[len(scheme):]
            break

    # strip trailing slashes (path-significant content is preserved; only the
    # trailing separator is dropped)
    s = s.rstrip("/")

    # collapse internal whitespace
    s = " ".join(s.split())

    return s


def answer_matches(submitted, accepted_raw, answer_type: str = None) -> bool:
    """
    Return True if ``submitted`` matches any of the ``;``-separated accepted answers
    after normalization. Mirrors the old Challenge.check_answer semantics (exact
    membership, case-insensitive, multiple accepted answers) with normalization added.
    """
    if accepted_raw is None:
        return False

    normalized_submitted = normalize_answer(submitted, answer_type)
    if normalized_submitted == "":
        return False

    for candidate in str(accepted_raw).split(";"):
        candidate = candidate.strip()
        if not candidate:
            continue
        if normalize_answer(candidate, answer_type) == normalized_submitted:
            return True
    return False


def explain_match(submitted, accepted_raw, answer_type: str = None) -> dict:
    """
    Like ``answer_matches``, but returns a structured explanation for an admin
    "test this answer" tool: the normalized submitted value, and for each accepted
    answer its normalized form and whether it matches. Consistent with
    ``answer_matches`` (same normalization, same empty-submission guard).
    """
    normalized_submitted = normalize_answer(submitted, answer_type)
    accepted = []
    matched_form = None
    for candidate in str(accepted_raw or "").split(";"):
        candidate = candidate.strip()
        if not candidate:
            continue
        nc = normalize_answer(candidate, answer_type)
        is_match = (nc == normalized_submitted and normalized_submitted != "")
        if is_match and matched_form is None:
            matched_form = candidate
        accepted.append({"raw": candidate, "normalized": nc, "matches": is_match})
    return {
        "submitted": submitted,
        "normalized_submitted": normalized_submitted,
        "matched": matched_form is not None,
        "matched_form": matched_form,
        "accepted": accepted,
    }
