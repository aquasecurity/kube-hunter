NAME := kube-hunter
SRC  := kube_hunter

.PHONY: deps
deps:
	pip install -r requirements-dev.txt

.PHONY: lint
lint:
	flake8 $(SRC)

.PHONY: build
build:
	python setup.py sdist bdist_wheel

.PHONY: install
install:
	pip install -e .

.PHONY: uninstall
uninstall:
	pip uninstall $(NAME)

.PHONY: publish
publish:
	twine upload dist/*

.PHONY: clean
clean:
	rm -rf build/ dist/ *.egg-info/ .eggs/ .pytest_cache/ .coverage
	find . -type d -name __pycache__ -exec rm -rf '{}' +
