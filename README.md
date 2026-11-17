# Django module starter (Copier template)

Makes a new reusable Django module: one app, packaged so any project can install it
with `uv add` (made for projects from the django-starter template, and working in any
Django project), with its own tests that run without a project.

Every new module comes with its checks from the first commit: gitleaks and ruff before
each commit, and on GitHub a CI workflow (tests on SQLite and PostgreSQL 18 with
coverage, pip-audit, a full secret scan, a check of what the package ships) and
Dependabot. Its tests also guard the rules a module keeps so it fits any project: it
loads from its own package, adds no `check --deploy` warning, and has nothing in its
templates a strict Content Security Policy blocks.

## Make a new module

```bash
uv tool install copier                                         # once
copier copy gh:Just-Sean/django-module-starter my-module       # the newest release
```

Copier asks:

| Question | What it's for |
| --- | --- |
| `module_name` | The human-readable name (e.g. "Site Branding"), shown in the admin |
| `package_name` | The Python import name and Django app label (e.g. `site_branding`). Names that would clash (Django's apps, `accounts`, `config`, Python keywords, the module's own tools) are refused; a Python standard-library name (`json`, `email`, …) fails the module's first test run |
| `distribution_name` | The name `uv add` installs (e.g. `site-branding`) |
| `description` | One sentence saying what the module does |
| `github_owner` | The GitHub account or organization the module will live under. No default: type your own |
| `license` | MIT, or proprietary (all rights reserved) |
| `copyright_year` | The year in the copyright notice (this year by default) |

Name the folder (and later the GitHub repository) after `distribution_name`: the
module's README uses that name in its install commands. Then follow the new module's
README, **Develop it**: `git init`, `uv lock`, the commit
check, the first commit, the GitHub repository and its settings. To answer
everything on the command line (e.g. in a script), give each answer with
`--data name=value`; `github_owner` and `license` have no default, so `--defaults`
alone stops and asks for them.

## Update a module when the starter improves

Commit the module first, then inside it:

```bash
copier update
```

Copier moves the module to the newest release and asks about any conflicts. The
module's README ("Updating from the starter") also says how to change the GitHub
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
  uncommitted changes included:
  `copier copy --vcs-ref=HEAD --data github_owner=me --data license=MIT /path/to/django-module-starter /tmp/try-it`,
  then run its checks (`git init`, `uv lock`, `uv run pytest --cov`, `uv run ruff check .`,
  `uv build`). Never use `--vcs-ref=HEAD` for a real module: Copier records an
  unreleased version and later refuses to update from it. The `.gitignore` keeps
  secrets and test output out of the copy.
- **Pinned versions** are kept in step by hand: the gitleaks `rev` in both
  `.pre-commit-config.yaml` files and `GITLEAKS_IMAGE` in the template's CI workflow;
  `UV_VERSION` in the workflow and the `uv_build` range in `pyproject.toml.jinja`.
- **Releasing:** an issue and a branch, then a pull request into `main`. After it's
  merged, tag `main` and push only the tag:
  `git switch main && git pull`, then `git tag vX.Y.Z` and `git push origin vX.Y.Z`.
  Modules update to the newest tag.
