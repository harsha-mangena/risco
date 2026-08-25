FROM python:3.12-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends curl git ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY packages/risco-core /opt/risco/packages/risco-core
RUN pip install --no-cache-dir "/opt/risco/packages/risco-core[sql,scan]"

ENV PYTHONUNBUFFERED=1
ENTRYPOINT ["python", "-m", "risco.actions_entry.index"]
