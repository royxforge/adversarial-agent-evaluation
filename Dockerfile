FROM python:3.10-slim
LABEL maintainer="Sourav Roy <sourav@accure.in>"
WORKDIR /app
COPY pyproject.toml .
RUN pip install --no-cache-dir .
COPY src/ ./src/
COPY scenarios/ ./scenarios/
COPY benchmarks/ ./benchmarks/
CMD ["uvicorn", "src.api.main:app", "--host", "0.0.0.0", "--port", "8000"]