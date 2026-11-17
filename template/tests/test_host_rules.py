"""Rules a module keeps so it fits any project that installs it, such as projects made
from django-starter: it never adds a `check --deploy` warning to the project, and its
templates have nothing a strict Content Security Policy blocks."""

import re
import string
from pathlib import Path

from django.core.management import call_command

SRC_DIR = Path(__file__).resolve().parent.parent / "src"

# A production project's security settings, as django-starter sets them, so any warning
# `check --deploy` still gives comes from the module.
PRODUCTION_SECURITY = {
    "DEBUG": False,
    "SECRET_KEY": "deploy-check-only-" + string.ascii_letters,  # long and varied, not a secret
    "ALLOWED_HOSTS": ["example.com"],
    "SECURE_SSL_REDIRECT": True,
    "SECURE_HSTS_SECONDS": 31536000,
    "SECURE_HSTS_INCLUDE_SUBDOMAINS": True,
    "SECURE_HSTS_PRELOAD": True,
    "SESSION_COOKIE_SECURE": True,
    "CSRF_COOKIE_SECURE": True,
    "X_FRAME_OPTIONS": "DENY",
}
CLICKJACKING_MIDDLEWARE = "django.middleware.clickjacking.XFrameOptionsMiddleware"

# Inline code a strict Content Security Policy blocks: <script> or <style> without a
# nonce (or a src), style="..." attributes, onclick=-style handlers, javascript: links.
BLOCKED = {
    "inline script": re.compile(r"<script(?![^>]*\b(?:src|nonce)=)[^>]*>", re.IGNORECASE),
    "inline style": re.compile(r"<style(?![^>]*\bnonce=)[^>]*>", re.IGNORECASE),
    "style attribute": re.compile(r"\sstyle\s*=", re.IGNORECASE),
    "event handler": re.compile(r"\son[a-z]+\s*=", re.IGNORECASE),
    "javascript: link": re.compile(r"javascript:", re.IGNORECASE),
}


def test_the_module_adds_no_deployment_warning(settings):
    for name, value in PRODUCTION_SECURITY.items():
        setattr(settings, name, value)
    settings.MIDDLEWARE = [*settings.MIDDLEWARE, CLICKJACKING_MIDDLEWARE]
    # Raises (and fails the test) on any warning, naming it.
    call_command("check", "--deploy", "--fail-level", "WARNING")


def blocked_in(html):
    """What in this HTML a strict CSP would block, by kind; empty when nothing would be."""
    found = {name: pattern.findall(html) for name, pattern in BLOCKED.items()}
    return {name: matches for name, matches in found.items() if matches}


def test_templates_have_nothing_a_strict_csp_blocks():
    # Inline scripts and styles need the page's nonce (nonce="{{ csp_nonce }}"); better,
    # put them in static files. See the README's rules.
    problems = {
        str(page.relative_to(SRC_DIR)): blocked
        for page in sorted(SRC_DIR.rglob("templates/**/*.html"))
        if (blocked := blocked_in(page.read_text(encoding="utf-8")))
    }
    assert problems == {}


def test_the_csp_check_finds_blocked_code():
    # So an empty result above means "nothing blocked", not "the check finds nothing".
    page = '<div style="x" onclick="go()"><script>1</script><a href="javascript:x">'
    found = set(blocked_in(page))
    assert found == {"inline script", "style attribute", "event handler", "javascript: link"}
    assert blocked_in('<script nonce="{{ csp_nonce }}">1</script>') == {}
