import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from actionguard.scanner import load_known_compromised, scan_repo

FIXTURES = Path(__file__).parent / "fixtures"


def test_flags_mutable_tag_as_unpinned():
    findings = scan_repo(FIXTURES)
    unpinned = [f for f in findings if "fake-action" in f.raw_ref and f.status == "UNPINNED"]
    assert len(unpinned) == 1
    assert unpinned[0].file.endswith("vulnerable-demo.yml")


def test_sha_pinned_action_is_not_flagged_unpinned():
    findings = scan_repo(FIXTURES)
    fixed = [f for f in findings if f.file.endswith("fixed-demo.yml") and "fake-action" in f.raw_ref]
    assert len(fixed) == 1
    assert fixed[0].status == "PINNED"
    assert fixed[0].severity == "INFO"


def test_known_compromised_action_is_flagged_critical():
    findings = scan_repo(FIXTURES)
    critical = [f for f in findings if f.owner_repo == "tj-actions/changed-files"]
    assert len(critical) == 1
    assert critical[0].severity == "CRITICAL"


def test_known_compromised_data_loads():
    known = load_known_compromised()
    assert "tj-actions/changed-files" in known


def _by_ref(findings, needle):
    matches = [f for f in findings if needle in f.raw_ref]
    assert len(matches) == 1, f"expected exactly one finding for {needle}, got {len(matches)}"
    return matches[0]


def test_trivy_action_tag_is_critical():
    # This is the case the original 2-entry list let through green.
    f = _by_ref(scan_repo(FIXTURES), "trivy-action@0.33.0")
    assert f.severity == "CRITICAL"
    assert f.status == "UNPINNED"


def test_trivy_action_vendor_safe_sha_is_info():
    f = _by_ref(scan_repo(FIXTURES), "57a97c7e7821a5776cebc9bb87c984fa69cba8f1")
    assert f.severity == "INFO"
    assert f.status == "PINNED"


def test_trivy_action_confirmed_malicious_sha_is_critical_even_when_pinned():
    f = _by_ref(scan_repo(FIXTURES), "c5967f85626795f647d4bf6eb67227f9b79e02f5")
    assert f.severity == "CRITICAL"
    assert f.status == "PINNED"


def test_unknown_sha_of_compromised_action_needs_verification():
    f = _by_ref(scan_repo(FIXTURES), "1111111111111111111111111111111111111111")
    assert f.severity == "MEDIUM"
    assert "verify" in f.message.lower()


def test_re_enabled_action_is_critical_for_any_ref():
    f = _by_ref(scan_repo(FIXTURES), "actions-cool/issues-helper@v3")
    assert f.severity == "CRITICAL"


def test_all_2026_incidents_are_in_the_list():
    known = load_known_compromised()
    for repo in (
        "aquasecurity/trivy-action", "aquasecurity/setup-trivy",
        "checkmarx/kics-github-action", "checkmarx/ast-github-action",
        "actions-cool/issues-helper", "actions-cool/maintain-one-comment",
        "codfish/semantic-release-action",
    ):
        assert repo in known, repo
