
install:
	@pip install \
	--force-reinstall \
	-e . \
	-r requirements-dev.txt

test:
	@python setup.py test

compile:
	@rm -f requirements-dev.txt
	@pip-compile requirements-dev.in

sync:
	@pip-sync requirements-dev.txt
	@pip install -e .
