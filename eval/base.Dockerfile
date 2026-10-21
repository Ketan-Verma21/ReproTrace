# Base image for the evaluation scenarios: Python, strace and ReproTrace.
# Built by eval/run_eval.py from the repository root:
#   docker build -f eval/base.Dockerfile -t reprotrace-eval-base .
FROM python:3.11-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends strace \
    && rm -rf /var/lib/apt/lists/*
COPY pyproject.toml README.md /src/
COPY src /src/src
RUN pip install --no-cache-dir /src && mkdir -p /app
