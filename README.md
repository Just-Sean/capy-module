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
