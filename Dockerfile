FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends git curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Native scanners (pip ones are installed below; CodeQL is opt-in - see docs).
RUN curl -sfL https://raw.githubusercontent.com/Bearer/bearer/main/contrib/install.sh | sh -s -- -b /usr/local/bin \
    && curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin \
    && curl -sfL https://raw.githubusercontent.com/securego/gosec/master/install.sh | sh -s -- -b /usr/local/bin

COPY pyproject.toml README.md ./
COPY emerald ./emerald

RUN pip install --no-cache-dir -e ".[llm,dashboard]" \
    && pip install --no-cache-dir semgrep bandit njsscan

EXPOSE 8501

CMD ["streamlit", "run", "emerald/app/dashboard.py", \
     "--server.port=8501", "--server.address=0.0.0.0"]
