FROM python:3.10-slim
LABEL maintainer="Sourav Roy <sourav@accure.in>"
WORKDIR /app

# Copy the package sources before installing: `pip install .` needs the
# `src/adversarial_agent_evaluation` tree to exist, otherwise the build
# produces an empty wheel and the API module cannot be imported at runtime.
COPY pyproject.toml ./
COPY src/ ./src/
RUN pip install --no-cache-dir .

COPY scenarios/ ./scenarios/
COPY benchmarks/ ./benchmarks/
CMD ["uvicorn", "adversarial_agent_evaluation.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
