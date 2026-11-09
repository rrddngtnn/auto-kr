export PYTHONPATH := packages
PY ?= /home/azuramaru/.hermes/tools/python-3.14.7+20260901-linux-x64/bin/python3

.PHONY: test hygiene init-social init-builder-id waf-free-gh-url

test:
	PYTHONPATH=packages $(PY) tests/test_auto_kr.py

hygiene:
	$(PY) scripts/public-hygiene-gate.py --repo-root .

init-social:
	PYTHONPATH=packages $(PY) -m auto_kr.cli init-social --idp $${IDP:-Github}

init-builder-id:
	PYTHONPATH=packages $(PY) -m auto_kr.cli init-builder-id

waf-free-gh-url:
	PYTHONPATH=packages $(PY) -m auto_kr.cli waf-free-gh-url
