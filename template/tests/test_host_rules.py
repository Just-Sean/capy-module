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
# The policy checked is django-starter's (config/settings/security.py), the strictest a
# module meets: scripts and styles only from the project's own site, or inline with the
# page's nonce; images from the site or data: URLs; no frames, video, audio, objects or
# manifests at all; forms post only to the site. So these are blocked:
# - inline <script> and <style> without the page's nonce. A script with a src and code
#   inside is reported too: browsers skip that code, but a conditional src would run it.
# - style="..." attributes and on...= attributes (onclick and the like)
# - javascript: URLs
# - loading from another site, or from a data: URL (except images)
# - frames, video, audio, objects, embeds and manifests
# Checked: every template file of the module. Not seen: CSS and JavaScript files, what
# inline code loads, and HTML built in Python.

TEMPLATE_FOLDERS = ("templates", "jinja2")
TEMPLATE_SUFFIXES = {
    ".html", ".htm", ".xhtml", ".djhtml", ".svg", ".xml", ".jinja", ".jinja2", ".j2",
}  # fmt: skip

# Never sent to the browser: a one-line {# #} comment (Django prints a multi-line one
# as text) and {% comment %} blocks. HTML comments are checked like everything else:
# browsers still run what's in them inside <script>.
NOT_RENDERED = re.compile(
    r"\{#[^\n]*?#\}|\{%-?\s*comment\b.*?%\}.*?\{%-?\s*endcomment\s*-?%\}", re.DOTALL
)
# The page's nonce, in Django or Jinja spelling, marked with text a template can't hold.
REAL_NONCE = re.compile(r"\{\{-?\s*(?:request\.)?csp_nonce\s*-?\}\}")
NONCE = "\x00nonce\x00"
# Other template code becomes a placeholder, keeping its quoted strings (a URL can be
# one) and, for {{ }}, a stand-in for what it outputs.
TEMPLATE_CODE = re.compile(r"\{%.*?%\}|\{\{.*?\}\}", re.DOTALL)
QUOTED_STRING = re.compile(r"\"([^\"]*)\"|'([^']*)'")
PLACEHOLDER = "￼"
OUTPUT = "output"
# Text inside a tag: quoted values (which may hold ">") or anything but quotes and ">".
INSIDE_TAG = r"(?:\"[^\"]*\"|'[^']*'|[^'\">])*"
# An opening tag: its name and the text of its attributes.
TAG = re.compile(rf"<([a-zA-Z][\w:-]*)({INSIDE_TAG})>")
# One attribute: its name and, if given, its value (quoted or not).
ATTRIBUTE = re.compile(r"""([^\s/=>"']+)(?:\s*=\s*("[^"]*"|'[^']*'|[^\s"'=<>`]+))?""")
# A <script> or <style> element (not <style-guide>): its attributes and the code inside.
ELEMENT_WITH_CODE = re.compile(
    rf"<(script|style)(?=[\s/>])({INSIDE_TAG})>(.*?)</\1\s*>", re.IGNORECASE | re.DOTALL
)
# Elements whose content is text, never tags.
TEXT_ONLY = re.compile(rf"<(textarea|title)(?=[\s/>])({INSIDE_TAG})>.*?</\1\s*>", re.I | re.S)
# Script types a browser runs (plus any JavaScript MIME type); others are data.
RUNNING_SCRIPT_TYPES = {"", "module", "importmap", "speculationrules"}

URL_ATTRIBUTES = {"href", "src", "action", "formaction", "xlink:href", "data", "poster"}
# Where each tag loads something from; a link only loads for these rel values.
LOADS_FROM = {
    "script": {"src", "href", "xlink:href"},
    "img": {"src", "srcset"},
    "source": {"srcset"},
    "input": {"src", "formaction"},
    "image": {"href", "xlink:href"},
    "feimage": {"href", "xlink:href"},
    "use": {"href", "xlink:href"},
    "link": {"href"},
    "form": {"action"},
    "button": {"formaction"},
    "base": {"href"},
}
LINK_RELS_THAT_LOAD = {"stylesheet", "preload", "modulepreload", "prefetch", "icon"}
DATA_URLS_ALLOWED = {"img", "source", "input", "image", "feimage"}  # images only
NEVER_ALLOWED = {"iframe", "frame", "video", "audio", "object", "embed"}
OTHER_SITE = ("http:", "https:", "//")
SNIPPET_LENGTH = 80


def placeholder_for(match):
    strings = [double or single for double, single in QUOTED_STRING.findall(match[0])]
    if match[0].startswith("{{"):
        strings.insert(0, OUTPUT)
    return f" {PLACEHOLDER}{PLACEHOLDER.join(strings)}{PLACEHOLDER} "


def as_rendered(html):
    """The template's HTML with what never reaches the browser removed, the page's nonce
    marked, and other template code reduced to placeholders (so a `>` inside {% %}
    can't hide the rest of a tag)."""
    html = NOT_RENDERED.sub(" ", html)
    html = REAL_NONCE.sub(NONCE, html)
    html = TEMPLATE_CODE.sub(placeholder_for, html)
    return TEXT_ONLY.sub(r"<\1\2></\1>", html)


def attributes(text):
    """A tag's attributes by name; like browsers, the first of a repeated one counts."""
    found = {}
    for name, value in ATTRIBUTE.findall(text):
        found.setdefault(name.lower(), value.strip("\"'"))
    return found


def url_pieces(value):
    """A URL as the browser reads it (entities decoded, spaces and control characters
    dropped, backslashes as slashes, lowercase), split where template code was."""
    clean = re.sub(r"[\x00-\x20]", "", html_entities.unescape(value))
    return clean.replace("\\", "/").lower().split(PLACEHOLDER)


def runs(attrs):
    kind = attrs.get("type", "").split(";")[0].strip().lower()
    return kind in RUNNING_SCRIPT_TYPES or "javascript" in kind or "ecmascript" in kind


def code_problems(tag, attrs, code):
    """What's wrong with the code inside a <script> or <style> element."""
    if not code.replace(PLACEHOLDER, "").strip() or (tag == "script" and not runs(attrs)):
        return []
    nonce = attrs.get("nonce", "")
    if nonce == NONCE:
        return []
    return ["wrong nonce"] if nonce.strip() else [f"inline {tag}"]


def loads_from_elsewhere(tag, value):
    for source in value.split(","):  # srcset lists several
        for piece in url_pieces(source):
            if piece.startswith(OTHER_SITE):
                return True
            if piece.startswith("data:") and tag not in DATA_URLS_ALLOWED:
                return True
    return False


def tag_problems(tag, attrs):
    """What's wrong with one opening tag."""
    problems = []
    rels = set(attrs.get("rel", "").lower().split())
    if "style" in attrs:
        problems.append("style attribute")
    if any(name.startswith("on") and name[2:].isalpha() for name in attrs):
        problems.append("event handler")
    urls = [attrs[name] for name in URL_ATTRIBUTES & attrs.keys()]
    if any(piece.startswith("javascript:") for value in urls for piece in url_pieces(value)):
        problems.append("javascript: link")
    if tag in NEVER_ALLOWED or (tag == "link" and "manifest" in rels):
        problems.append("frame, media, object or manifest")
    loads = LOADS_FROM.get(tag, set()) & attrs.keys()
    if tag == "link" and not LINK_RELS_THAT_LOAD & rels:
        loads = set()
    if any(loads_from_elsewhere(tag, attrs[name]) for name in loads):
        problems.append("other site or data: URL")
    return problems


def snippet(text):
    text = text.replace(NONCE, "{{ csp_nonce }}").replace(PLACEHOLDER, "")
    return text[:SNIPPET_LENGTH]


def blocked_in(html):
    """What in this template a strict CSP would block, by kind; empty when nothing would
    be."""
    html = as_rendered(html)
    found = {}
    for match in ELEMENT_WITH_CODE.finditer(html):
        tag, attrs, code = match[1].lower(), attributes(match[2]), match[3]
        for problem in code_problems(tag, attrs, code):
            found.setdefault(problem, []).append(snippet(match[0]))
    for match in TAG.finditer(html):
        for problem in tag_problems(match[1].lower(), attributes(match[2])):
            found.setdefault(problem, []).append(snippet(match[0]))
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


ELSEWHERE = "other site or data: URL"
NOT_ALLOWED = "frame, media, object or manifest"


# So an empty result above means "nothing blocked", not "the check finds nothing".
@pytest.mark.parametrize(
    ("html", "kind"),
    [
        ("<script>alert(1)</script>", "inline script"),
        ("<SCRIPT>alert(1)</SCRIPT>", "inline script"),
        ('<script data-src="x.js">alert(1)</script>', "inline script"),
        ('<script nonce="">alert(1)</script>', "inline script"),
        ('<script {% if a %}src="a.js"{% endif %}>alert(1)</script>', "inline script"),
        ('<script src="/x.js">alert(1)</script>', "inline script"),
        ("<script>{{ data }}</script>", "inline script"),
        ('<script>{% include "m/inline.js" %}</script>', "inline script"),
        ("<script><!--\ngo();\n//--></script>", "inline script"),
        ("<svg><script>go()</script></svg>", "inline script"),
        ("{% block extra_js %}<script>go()</script>{% endblock %}", "inline script"),
        ("{# start\n<script>go()</script>\nend #}", "inline script"),
        ('<script nonce="abc123">alert(1)</script>', "wrong nonce"),
        ('<script nonce="CSP-NONCE">alert(1)</script>', "wrong nonce"),
        ('<script nonce="{{ other }}">alert(1)</script>', "wrong nonce"),
        ("<style>p { color: red }</style>", "inline style"),
        ('<style nonce="abc123">p {}</style>', "wrong nonce"),
        ('<p style="color: red">', "style attribute"),
        ("<p style=color:red>", "style attribute"),
        ('<div/style="x">', "style attribute"),
        ('<p {% if n > 1 %}class="many"{% endif %} style="color: red">', "style attribute"),
        ('<div {% if a %}style="x"{% endif %}>', "style attribute"),
        ('<button onclick="go()">', "event handler"),
        ("<BUTTON ONCLICK='go()'>", "event handler"),
        ('<button\n  type="button"\n  onclick="go()"\n>Go</button>', "event handler"),
        ('<div/onclick = "go()">', "event handler"),
        ('<button {% if n > 0 %}disabled{% endif %} onclick="go()">', "event handler"),
        ('<div title="{% translate "a > b" %}" onclick="go()">', "event handler"),
        ('<svg onload="go()"></svg>', "event handler"),
        ("<!-- <p onclick='x'> -->", "event handler"),
        ('<a href="javascript:go()">', "javascript: link"),
        ("<a href=javascript:go()>x</a>", "javascript: link"),
        ('<a href="  JavaScript:go()">', "javascript: link"),
        ('<a href="javascript&#58;go()">', "javascript: link"),
        ('<a href="javascript&colon;go()">x</a>', "javascript: link"),
        ('<a href="java\tscript:go()">', "javascript: link"),
        ('<a href="javascript:go()" href="/">x</a>', "javascript: link"),
        ('<a href="{% if x %}#{% else %}javascript:void(0){% endif %}">', "javascript: link"),
        ('<a href="{% firstof a "javascript:void(0)" %}">', "javascript: link"),
        ('<svg><a xlink:href="javascript:go()"><text>x</text></a></svg>', "javascript: link"),
        ('<form action="javascript:go()">', "javascript: link"),
        ('<script src="https://cdn.example.com/x.js"></script>', ELSEWHERE),
        ('<script src="//cdn.example.com/x.js"></script>', ELSEWHERE),
        ('<script src="\\\\cdn.example.com/x.js"></script>', ELSEWHERE),
        ('<script src="/\\cdn.example.com/x.js"></script>', ELSEWHERE),
        ('<script src="data:text/javascript,go()"></script>', ELSEWHERE),
        ('<script src="https://{{ host }}/x.js"></script>', ELSEWHERE),
        ('<script src="{% if debug %}/x.js{% else %}https://cdn.example.com/x.js{% endif %}">'
         "</script>", ELSEWHERE),
        ('<img src="{{ MEDIA_PREFIX }}//cdn.example.com/a.png" alt="">', ELSEWHERE),
        ('<link rel="stylesheet" href="https://fonts.example.com/css">', ELSEWHERE),
        ('<link rel="stylesheet" href="data:text/css,p{}">', ELSEWHERE),
        ('<img src="https://example.com/p.png" alt="">', ELSEWHERE),
        ('<img srcset="/a.png 1x, https://example.com/b.png 2x" alt="">', ELSEWHERE),
        ('<svg><image href="https://cdn.example.com/a.png"/></svg>', ELSEWHERE),
        ('<svg><use xlink:href="https://cdn.example.com/s.svg#i"/></svg>', ELSEWHERE),
        ('<svg><script href="https://cdn.example.com/x.js"/></svg>', ELSEWHERE),
        ('<form method="post" action="https://pay.example.com/">', ELSEWHERE),
        ('<button formaction="https://pay.example.com/">', ELSEWHERE),
        ('<base href="https://cdn.example.com/">', ELSEWHERE),
        ('<iframe src="/embed/"></iframe>', NOT_ALLOWED),
        ('<iframe srcdoc="&lt;script&gt;go()&lt;/script&gt;"></iframe>', NOT_ALLOWED),
        ('<video src="/static/m/intro.mp4"></video>', NOT_ALLOWED),
        ('<object data="/static/m/x.pdf"></object>', NOT_ALLOWED),
        ('<link rel="manifest" href="/manifest.json">', NOT_ALLOWED),
    ],
)  # fmt: skip
def test_the_csp_check_finds_blocked_code(html, kind):
    assert kind in blocked_in(html), html


@pytest.mark.parametrize(
    "html",
    [
        '<script nonce="{{ csp_nonce }}">1</script>',
        '<script nonce="{{ request.csp_nonce }}">1</script>',
        "<script nonce={{ csp_nonce }}>go()</script>",
        '<script nonce="{{- csp_nonce }}">go()</script>',
        "<script src=\"{% static 'x.js' %}\" defer></script>",
        '<style nonce="{{ csp_nonce }}">p {}</style>',
        "<style-guide>x</style-guide><style nonce=\"{{ csp_nonce }}\">p{}</style>",
        '<script type="application/json">{"a": 1}</script>',
        '<script type="application/json; charset=utf-8">{"a": 1}</script>',
        '<script type="text/x-template" id="t"><div>{{ x }}</div></script>',
        "<script>{% if a %}{% endif %}</script>",
        '{{ data|json_script:"m-data" }}',
        '<p {% if n > 1 %}class="many"{% endif %}>x</p>',
        '<input data-style="x" data-onclick="y">',
        '<a href="/online=1">x</a>',
        '<a href="https://example.com/">A link to another site</a>',
        '<link rel="canonical" href="https://example.com/">',
        '<link rel="preconnect" href="https://example.com">',
        '<img src="data:image/svg+xml,%3Csvg%3E" alt="">',
        "<form method=\"post\" action=\"{% url 'm:save' %}\">{% csrf_token %}</form>",
        '<textarea name="t"><p style="x"></textarea>',
        "<p>Turn this on = yes, javascript: off</p>",
        "{# <script>commented out</script> #}",
        "{% comment %}<p style='x'>{% endcomment %}",
    ],
)  # fmt: skip
def test_the_csp_check_allows_what_a_strict_csp_allows(html):
    assert blocked_in(html) == {}, html


def test_every_template_file_is_checked(tmp_path):
    names = [
        "jinja2/m/page.html",
        "jinja2/m/page.j2",
        "templates/m/feed.xml",
        "templates/m/icon.svg",
        "templates/m/page.htm",
        "templates/m/page.html",
        "templates/m/page.jinja",
    ]
    for name in [*names, "templates/m/email.txt"]:
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / name).write_text("<script>alert(1)</script>", encoding="utf-8")
    checked = [str(path.relative_to(tmp_path)) for path in template_files(tmp_path)]
    assert checked == names
