FROM python:3.12-slim

WORKDIR /app

# git for cloning targets; scanners are pip-installed below
RUN apt-get update && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY emerald ./emerald

RUN pip install --no-cache-dir -e ".[llm,dashboard]" \
    && pip install --no-cache-dir semgrep bandit njsscan

EXPOSE 8501

CMD ["streamlit", "run", "emerald/app/dashboard.py", \
     "--server.port=8501", "--server.address=0.0.0.0"]
