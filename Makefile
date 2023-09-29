.PHONY: build
build:
	poetry lock
	poetry install
	poetry run poe build

.PHONY: clean
clean:
	rm cloud-hunter
