.SILENT:

NAME            := kube-hunter
SRC             := kube_hunter
ENTRYPOINT      := $(SRC)/__main__.py
DIST            := dist
COMPILED        := $(DIST)/$(NAME)
STATIC_COMPILED := $(COMPILED).static


.PHONY: deps
deps:
	pip install -r requirements-dev.txt

.PHONY: lint
lint:
	flake8 $(SRC)

.PHONY: build
build:
	python setup.py sdist bdist_wheel

.PHONY: pyinstaller
pyinstaller: deps
	python setup.py pyinstaller

.PHONY: staticx_deps
staticx_deps:
	command -v patchelf > /dev/null 2>&1 || (echo "patchelf is not available. install it in order to use staticx" && false)

.PHONY: pyinstaller_static
pyinstaller_static: staticx_deps pyinstaller
	staticx $(COMPILED) $(STATIC_COMPILED)

.PHONY: install
install:
	pip install .

.PHONY: uninstall
uninstall:
	pip uninstall $(NAME)

.PHONY: publish
publish:
	twine upload dist/*

.PHONY: clean
clean:
	rm -rf build/ dist/ *.egg-info/ .eggs/ .pytest_cache/ .coverage *.spec
	find . -type d -name __pycache__ -exec rm -rf '{}' +
