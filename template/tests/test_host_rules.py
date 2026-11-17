"""Rules a module keeps so it fits any project that installs it, such as projects made
from django-starter: it never adds a `check --deploy` warning to the project, and its
templates have nothing a strict Content Security Policy blocks."""

import html as html_entities
import re
import string
from pathlib import Path

import pytest
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


def test_the_module_adds_no_deployment_warning(settings):
    for name, value in PRODUCTION_SECURITY.items():
        setattr(settings, name, value)
    settings.MIDDLEWARE = [*settings.MIDDLEWARE, CLICKJACKING_MIDDLEWARE]
    # Raises (and fails the test) on any warning, naming it.
    call_command("check", "--deploy", "--fail-level", "WARNING")


# --- The templates, as a strict Content Security Policy sees them ----------------------
# Blocked: inline <script> and <style> without the page's nonce, style="..." attributes,
# onclick=-style handlers, javascript: links, and scripts, styles, fonts, images, frames
# or media from other sites. Checked on every template file of the module.

TEMPLATE_FOLDERS = ("templates", "jinja2")
TEMPLATE_SUFFIXES = {".html", ".htm", ".svg", ".xml"}

NOT_RENDERED = re.compile(
    r"\{#.*?#\}|\{%\s*comment\b.*?%\}.*?\{%\s*endcomment\s*%\}|<!--.*?-->", re.DOTALL
)
REAL_NONCE = re.compile(r"\{\{\s*(?:request\.)?csp_nonce\s*\}\}")
NONCE = "CSP-NONCE"
TEMPLATE_CODE = re.compile(r"\{%.*?%\}|\{\{.*?\}\}", re.DOTALL)
QUOTED_OR_PLAIN = r"(?:\"[^\"]*\"|'[^']*'|[^'\">])*"
TAG = re.compile(rf"<([a-zA-Z][\w:-]*)({QUOTED_OR_PLAIN})>")
ATTRIBUTE = re.compile(r"""([^\s/=>"']+)(?:\s*=\s*("[^"]*"|'[^']*'|[^\s"'=<>`]+))?""")
ELEMENT_WITH_CODE = re.compile(
    rf"<(script|style)\b({QUOTED_OR_PLAIN})>(.*?)</\1\s*>", re.IGNORECASE | re.DOTALL
)
DATA_SCRIPT_TYPES = {"application/json", "application/ld+json"}  # data, never run
URL_ATTRIBUTES = {"href", "src", "action", "formaction", "xlink:href", "data", "poster"}
# What each tag loads from its URL; a link only loads for these rel values.
LOADS_FROM = {
    "script": {"src"},
    "img": {"src", "srcset"},
    "iframe": {"src"},
    "frame": {"src"},
    "source": {"src", "srcset"},
    "video": {"src", "poster"},
    "audio": {"src"},
    "track": {"src"},
    "embed": {"src"},
    "object": {"data"},
    "input": {"src"},
    "link": {"href"},
}
LINK_RELS_THAT_LOAD = {"stylesheet", "preload", "modulepreload", "prefetch", "icon", "manifest"}
OTHER_SITE = ("http:", "https:", "//")


def as_rendered(html):
    """The template's HTML with what never reaches the browser removed, the page's nonce
    marked, and other template code reduced to a placeholder (so a `>` inside {% %}
    can't hide the rest of a tag)."""
    html = NOT_RENDERED.sub(" ", html)
    html = REAL_NONCE.sub(NONCE, html)
    return TEMPLATE_CODE.sub(" T ", html)


def attributes(text):
    return {name.lower(): value.strip("\"'") for name, value in ATTRIBUTE.findall(text)}


def url(value):
    """A URL as the browser reads it: entities decoded, spaces and control characters
    dropped, lowercase."""
    return re.sub(r"[\x00-\x20]", "", html_entities.unescape(value)).lower()


def code_problems(tag, attrs, code):
    if not code.strip() or attrs.get("type", "").lower() in DATA_SCRIPT_TYPES:
        return []
    if attrs.get("nonce") == NONCE:
        return []
    if attrs.get("nonce", "").strip():
        return ["wrong nonce"]
    return [f"inline {tag}"]


def tag_problems(tag, attrs):
    problems = []
    if "style" in attrs:
        problems.append("style attribute")
    if any(name.startswith("on") and name[2:].isalpha() for name in attrs):
        problems.append("event handler")
    if any(url(attrs[name]).startswith("javascript:") for name in URL_ATTRIBUTES & attrs.keys()):
        problems.append("javascript: link")
    loads = LOADS_FROM.get(tag, set())
    if tag == "link" and not LINK_RELS_THAT_LOAD & set(attrs.get("rel", "").lower().split()):
        loads = set()
    sources = [part for name in loads & attrs.keys() for part in attrs[name].split(",")]
    if any(url(source).startswith(OTHER_SITE) for source in sources):
        problems.append("other site")
    return problems


def blocked_in(html):
    """What in this template a strict CSP would block, by kind; empty when nothing would
    be."""
    html = as_rendered(html)
    found = {}
    for match in ELEMENT_WITH_CODE.finditer(html):
        tag, attrs, code = match[1].lower(), attributes(match[2]), match[3]
        for problem in code_problems(tag, attrs, code):
            found.setdefault(problem, []).append(match[0][:80])
    for match in TAG.finditer(html):
        for problem in tag_problems(match[1].lower(), attributes(match[2])):
            found.setdefault(problem, []).append(match[0][:80])
    return found


def template_files(root):
    return sorted(
        path
        for folder in TEMPLATE_FOLDERS
        for path in root.rglob(f"{folder}/**/*")
        if path.is_file() and path.suffix.lower() in TEMPLATE_SUFFIXES
    )


def test_templates_have_nothing_a_strict_csp_blocks():
    # Inline scripts and styles need the page's nonce (nonce="{{ csp_nonce }}"); better,
    # put them in static files. Load everything from the project's own site. See the
    # README's rules.
    problems = {
        str(page.relative_to(SRC_DIR)): blocked
        for page in template_files(SRC_DIR)
        if (blocked := blocked_in(page.read_text(encoding="utf-8")))
    }
    assert problems == {}


# So an empty result above means "nothing blocked", not "the check finds nothing".
@pytest.mark.parametrize(
    ("html", "kind"),
    [
        ("<script>alert(1)</script>", "inline script"),
        ('<script data-src="x.js">alert(1)</script>', "inline script"),
        ('<script nonce="">alert(1)</script>', "inline script"),
        ('<script {% if a %}src="a.js"{% endif %}>alert(1)</script>', "inline script"),
        ("<script>{{ data }}</script>", "inline script"),
        ('<script nonce="abc123">alert(1)</script>', "wrong nonce"),
        ('<script nonce="{{ other }}">alert(1)</script>', "wrong nonce"),
        ("<style>p { color: red }</style>", "inline style"),
        ('<style nonce="abc123">p {}</style>', "wrong nonce"),
        ('<p style="color: red">', "style attribute"),
        ('<div/style="x">', "style attribute"),
        ('<p {% if n > 1 %}class="many"{% endif %} style="color: red">', "style attribute"),
        ('<div {% if a %}style="x"{% endif %}>', "style attribute"),
        ('<button onclick="go()">', "event handler"),
        ('<div/onclick = "go()">', "event handler"),
        ('<button {% if n > 0 %}disabled{% endif %} onclick="go()">', "event handler"),
        ('<a href="javascript:go()">', "javascript: link"),
        ('<a href="  JavaScript:go()">', "javascript: link"),
        ('<a href="javascript&#58;go()">', "javascript: link"),
        ('<a href="java\tscript:go()">', "javascript: link"),
        ('<script src="https://cdn.example.com/x.js"></script>', "other site"),
        ('<script src="//cdn.example.com/x.js"></script>', "other site"),
        ('<link rel="stylesheet" href="https://fonts.example.com/css">', "other site"),
        ('<img src="https://example.com/p.png" alt="">', "other site"),
        ('<img srcset="/a.png 1x, https://example.com/b.png 2x" alt="">', "other site"),
        ('<iframe src="https://example.com/"></iframe>', "other site"),
        ('<script src="https://{{ host }}/x.js"></script>', "other site"),
    ],
)
def test_the_csp_check_finds_blocked_code(html, kind):
    assert kind in blocked_in(html), html


@pytest.mark.parametrize(
    "html",
    [
        '<script nonce="{{ csp_nonce }}">1</script>',
        '<script nonce="{{ request.csp_nonce }}">1</script>',
        "<script src=\"{% static 'x.js' %}\" defer></script>",
        '<style nonce="{{ csp_nonce }}">p {}</style>',
        '<script type="application/json">{"a": 1}</script>',
        '<p {% if n > 1 %}class="many"{% endif %}>x</p>',
        '<input data-style="x" data-onclick="y">',
        '<a href="/online=1">x</a>',
        '<a href="https://example.com/">A link to another site</a>',
        '<link rel="canonical" href="https://example.com/">',
        "<p>Turn this on = yes, javascript: off</p>",
        "{# <script>commented out</script> #}",
        "{% comment %}<p style='x'>{% endcomment %}",
        "<!-- <p onclick='x'> -->",
    ],
)
def test_the_csp_check_allows_what_a_strict_csp_allows(html):
    assert blocked_in(html) == {}, html


def test_every_template_file_is_checked(tmp_path):
    for name in [
        "templates/m/page.html",
        "templates/m/page.htm",
        "templates/m/icon.svg",
        "templates/m/feed.xml",
        "jinja2/m/page.html",
    ]:
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / name).write_text("<script>alert(1)</script>", encoding="utf-8")
    (tmp_path / "templates/m/email.txt").write_text("Hello", encoding="utf-8")
    checked = [str(path.relative_to(tmp_path)) for path in template_files(tmp_path)]
    assert checked == [
        "jinja2/m/page.html",
        "templates/m/feed.xml",
        "templates/m/icon.svg",
        "templates/m/page.htm",
        "templates/m/page.html",
    ]
