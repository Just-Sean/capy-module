# Django module starter (Copier template)

Makes a new reusable Django module: one app, packaged so any project can
install it with `uv add`, with its own tests that run without a project.

```bash
uv tool install copier                                   # once
copier copy ./django-module-starter ./dj-my-module       # asks for the names
```

Copier needs this template folder to be a Git repository with at least one
commit. Tag releases (`git tag v0.1.0`) so modules can `copier update` to a
known version.

Every new module comes with its checks from the first commit: gitleaks and ruff before
each commit, and on GitHub a CI workflow (tests on SQLite and PostgreSQL 18 with
coverage, pip-audit, a full secret scan, a check of what the package ships) and
Dependabot. See the module's own README, "Develop it".

## Working on the starter

The starter is under the MIT license (`LICENSE`). Its own commit check (gitleaks, so no
secret is committed here either) is set up once per clone:

```bash
uv tool install pre-commit      # once per machine
pre-commit install              # once per clone
```

Its `.gitignore` keeps secrets and test output out of git. That matters for new modules
too: `copier copy --vcs-ref=HEAD` from a local checkout copies uncommitted files.
