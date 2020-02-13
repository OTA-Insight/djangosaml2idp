
install:
	@pip install \
	-e . \
	-r requirements-dev.txt
	@pre-commit install
