.PHONY: install test lint run docker-build docker-up

install:
	pip install -e .

test:
	pytest tests/

lint:
	ruff check src/

run:
	python src/api/main.py

docker-build:
	docker-compose build

docker-up:
	docker-compose up

docker-down:
	docker-compose down