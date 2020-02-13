
install:
	@pip install -e .
	@pip install --upgrade -r requirements-dev.txt

test:
	@python setup.py test

compile:
	@rm -f requirements-dev.txt
	@pip-compile requirements-dev.in