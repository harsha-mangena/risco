FROM python:3.15-slim

ARG OASDIFF_VERSION=v1.29.1
ARG BUF_VERSION=v1.47.2

RUN apt-get update \
 && apt-get install -y --no-install-recommends curl git ca-certificates \
 && rm -rf /var/lib/apt/lists/*

RUN curl -sSfL "https://github.com/oasdiff/oasdiff/releases/download/${OASDIFF_VERSION}/oasdiff_${OASDIFF_VERSION#v}_linux_amd64.tar.gz" \
      | tar xz -C /usr/local/bin oasdiff \
 && chmod +x /usr/local/bin/oasdiff

RUN curl -sSfL "https://github.com/bufbuild/buf/releases/download/${BUF_VERSION}/buf-Linux-x86_64" \
      -o /usr/local/bin/buf && chmod +x /usr/local/bin/buf

COPY packages/risco-core /opt/risco/packages/risco-core
RUN pip install --no-cache-dir "/opt/risco/packages/risco-core[sql,scan]"

ENV PYTHONUNBUFFERED=1
ENTRYPOINT ["python", "-m", "risco.actions_entry.check"]
