
install:
	@pip install -e .
	@pip install --upgrade -r requirements-dev.txt
	@pre-commit install

test:
	@python setup.py test

compile:
	@rm -f requirements-dev.txt
	@pip-compile requirements-dev.in

sync:
	@pip-sync requirements-dev.txt
	@pip install -e .
