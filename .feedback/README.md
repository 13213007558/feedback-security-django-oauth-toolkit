# Feedback task starting environment

Upstream: https://github.com/django-oauth/django-oauth-toolkit
Upstream commit: `285ba9c38306bccf798cc4f9fe64fbbae8659e40`
Prepared on macOS with the Python version recorded in the environment plan. No external database, queue, or cloud account is required.

The dependency file pins the installed runtime and test packages for the selected baseline. It is not a claim that all optional upstream test suites are installed.

From the repository root:

```sh
export NO_INTERNET=1 TZ=UTC DJANGO_SETTINGS_MODULE=tests.settings UV_NO_CONFIG=1

uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -q -o addopts= --ds=tests.settings tests/test_generator.py tests/test_www_authenticate.py
```

Scope note: The scope is the command below, not all optional upstream integrations.

Observed baseline (2026-11-12): `13 passed in 2.62s`
Whole-command wall time: 3.116 seconds, exit code 0. This is one local measurement, not a runtime guarantee. The first install is excluded.

This seed adds preparation metadata only. Application sources and upstream tests are unchanged; there is no task solution in this commit.
