# Django module starter (Copier template)

Makes a new reusable Django module: one app, packaged so any project can install it
with `uv add` (made for projects from the django-starter template, and working in any
Django project), with its own tests that run without a project.

Every new module comes with its checks from the first commit: gitleaks and ruff before
each commit, and on GitHub a CI workflow (tests on SQLite and PostgreSQL 18 with
coverage, also on the lowest versions allowed, pip-audit, a full secret scan, a check
of what the package ships) and Dependabot. Its tests also guard the rules a module
keeps so it fits any project: it loads from its own package, adds no `check --deploy`
warning, and has nothing in its templates a strict Content Security Policy blocks. Its
README holds the rules for everything a module adds: pages, security, the database,
releases.

## Architecture

- **`copier.yml`** asks the questions and checks the answers (refusing names that
  would clash with what projects install, and characters that would hide in code).
- **`template/`** is copied into each new module: files ending in `.jinja` are filled
  in with the answers, the rest are copied as they are.
- **Copier** was chosen so modules can take in the starter's later improvements with
  `copier update`, keeping their own changes.
- Modules are released as git tags and installed from GitHub (never the public PyPI),
  and built for projects from the django-starter template: they fit its settings
  layout, its strict Content Security Policy, its private file storage and its
  database login that isn't a superuser.

## Make a new module

You need uv, git and Copier (`uv tool install copier`, once). Then, naming the folder
after the module's `distribution_name`:

```bash
copier copy gh:Just-Sean/django-module-starter site-branding   # the newest release
```

Copier asks:

| Question | What it's for |
| --- | --- |
| `module_name` | The human-readable name (e.g. "Site Branding"), shown in the admin |
| `package_name` | The Python import name and Django app label (e.g. `site_branding`). Names that would clash (Django's apps, `accounts`, `config`, Python keywords, the packages django-starter projects and the module itself install) are refused; a Python standard-library name (`json`, `email`, …) fails the module's first test run |
| `distribution_name` | The name `uv add` installs (e.g. `site-branding`). Names of packages django-starter projects or the module install are refused |
| `description` | One sentence saying what the module does |
| `github_owner` | The GitHub account or organization the module will live under, also the copyright holder in its `LICENSE`. No default: type your own |
| `license` | MIT, or proprietary (all rights reserved) |
| `copyright_year` | The year in the copyright notice (this year by default) |

Name the folder (and later the GitHub repository) after `distribution_name`: the
module's README uses that name in its install commands. Then follow the new module's
README, **Develop it**: `git init -b main`, `uv lock`, the commit check, the first
commit, the GitHub repository and its settings. To answer everything on the command
line (e.g. in a script), give each answer with `--data name=value`; `github_owner` and
`license` have no default, so `--defaults` without them fails with an error naming
the missing answer.

## Update a module when the starter improves

Inside the module, on a branch with everything committed:

```bash
copier update
```

Copier asks its questions again (press Enter to keep each answer) and moves the module
to the newest release. Where the module and the starter both changed a file, it writes
both versions between `<<<<<<<` and `>>>>>>>` lines to sort out by hand. The module's
README ("Updating from the starter") has every step, and how to change the GitHub
owner, license or year later.

## Working on the starter

The starter is under the MIT license (`LICENSE`). Its own commit check (gitleaks, so no
secret is committed here either) is set up once per clone:

```bash
uv tool install pre-commit      # once per machine
pre-commit install              # once per clone
```

- Files under `template/` ending in `.jinja` are filled in by Copier and lose the
  ending in the module; other files are copied as they are. The CI workflow is
  deliberately not `.jinja`, so GitHub's `${{ }}` expressions stay untouched.
- **Trying changes before a release:** make a throwaway module from your working copy,
  uncommitted changes included: `copier copy --vcs-ref=HEAD --data github_owner=me
  --data license=MIT /path/to/django-module-starter /tmp/try-it`, then run its checks
  with uv 0.12, which modules require (`git init -b main`, `uv lock`, `uv run pytest
  --cov`, `uv run ruff check .`, `uv build`). Never use `--vcs-ref=HEAD` for a real
  module: Copier records an unreleased version and later refuses to update from it. The
  starter's own `.gitignore` keeps secrets and test output out of the copy.
- **Pinned versions** are kept in step by hand: the gitleaks `rev` in both
  `.pre-commit-config.yaml` files and `GITLEAKS_IMAGE` in the template's CI workflow;
  `UV_VERSION` in the workflow, `required-version` and the `uv_build` range in
  `pyproject.toml.jinja`, and the `uv self update` version in `template/README.md.jinja`.
- **Refused names** (`taken_package_names` and `taken_distribution_names` in
  `copier.yml`): besides Django's apps and a project's own names, every package a
  django-starter project and a module install, since a module with the same name would
  replace it in projects. Check them whenever either template's dependencies change or
  are upgraded:
  1. Make a throwaway project from your django-starter working copy
     (`copier copy --vcs-ref=HEAD /path/to/django-starter /tmp/p`) and a throwaway
     module as in "Trying changes before a release" above; run `uv sync` in each.
  2. Compare the package names in each `uv.lock` with `taken_distribution_names`, the
     top-level names in each `.venv/lib/python3.*/site-packages` (folders and `.py`
     files, not `*.dist-info`) with `taken_package_names`, and the app labels the
     project installs (`label = ` in each app's `apps.py`) with `taken_package_names`
     too.
  3. Add any name that's missing. Skip the project's and module's own names and names
     the name check refuses anyway (starting with `_`, or with a dot or capitals, such
     as `psycopg_binary.libs`). A package a lock lists only for another system (e.g.
     `colorama` on Windows) isn't in your site-packages: look up its import name on its
     project page and add that too. Remove a name only when neither template installs
     it any more.
- **Releasing:** an issue and a branch; before the pull request, make a throwaway
  module from it and run its checks (above), and update the pinned versions to the
  newest ones. Then a pull request into `main`. After it's merged, tag `main` and push
  only the tag: `git switch main && git pull`, then `git tag vX.Y.Z` and
  `git push origin vX.Y.Z`. Modules update to the newest tag. Write release notes for
  the tag on GitHub (Releases, "Draft a new release"): what changed, and what module
  owners must do after `copier update` (a new uv version, renamed CI checks to update
  in their branch protection, and the like).
