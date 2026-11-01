.PHONY: install test lint run demo demo-defended docker-build docker-up docker-down

install:
	pip install -e .

test:
	pytest tests/

lint:
	ruff check src/

demo:
	python -m adversarial_agent_evaluation.cli benchmark

demo-defended:
	python -m adversarial_agent_evaluation.evaluation.defended_comparison

run:
	uvicorn adversarial_agent_evaluation.api.main:app --host 0.0.0.0 --port 8000

docker-build:
	docker-compose build

docker-up:
	docker-compose up

docker-down:
	docker-compose down