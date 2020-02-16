
# This target inits the repo
install:
	@pip install \
	--force-reinstall \
	-e .[testing] \
	-r requirements-dev.txt
	@pre-commit install

# Run entire test suite
test:
	@python setup.py test

# Recompiles dev dependencies
compile:
	@rm -f requirements-dev.txt
	@pip-compile requirements-dev.in

# Updates virtualenv with new dependencies
#  pip-sync will uninstall anything not in the given requirements files
#  and so you have to reinstall the package deps.
sync:
	@pip-sync requirements-dev.txt
	@pip install -e .[testing]

lint:
	@pylama djangosaml2idp

# Clean up files from development
clean:
	@rm -rf \
	.pytest_cache \
	.tox \
	dist
