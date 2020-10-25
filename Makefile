.PHONY: flake8 isort black format lint

PACKAGE_NAME=cryptopals

flake8:
	flake8 $(PACKAGE_NAME) *.py

isort:
	isort --atomic $(PACKAGE_NAME) *.py $(ARGS)

isort-check:
	$(MAKE) isort ARGS='--check-only --diff'

black:
	black $(PACKAGE_NAME) *.py $(ARGS)

black-check:
	$(MAKE) black ARGS='--check --verbose --diff'

autoflake:
	autoflake --in-place --remove-all-unused-imports $(PACKAGE_NAME)/*.py $(ARGS)

format: black isort autoflake

lint: flake8 black-check isort-check


test:
	pytest test $(ARGS) \
		--disable-warnings

coverage: lint
	coverage run --source $(PACKAGE_NAME) -m \
		pytest test $(ARGS)
	coverage report --show-missing --fail-under 10


docker-compose:
	docker-compose up $(ARGS)


# local, if exists
-include Makefile.local
