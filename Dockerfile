FROM python:3.12.13-slim-bookworm@sha256:8a7e7cc04fd3e2bd787f7f24e22d5d119aa590d429b50c95dfe12b3abe52f48b AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /build
COPY requirements-build.lock ./
RUN python -m pip install --no-cache-dir -r requirements-build.lock
COPY pyproject.toml README.md LICENSE ./
COPY src/ ./src/
RUN python -m pip wheel --no-deps --no-build-isolation --wheel-dir /wheels .

FROM python:3.12.13-slim-bookworm@sha256:8a7e7cc04fd3e2bd787f7f24e22d5d119aa590d429b50c95dfe12b3abe52f48b

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN groupadd --gid 10001 detector \
    && useradd --uid 10001 --gid detector --no-create-home --shell /usr/sbin/nologin detector

COPY requirements-runtime.lock /tmp/requirements-runtime.lock
COPY --from=builder /wheels /tmp/wheels
RUN python -m pip install --no-cache-dir -r /tmp/requirements-runtime.lock \
    && python -m pip install --no-cache-dir --no-deps /tmp/wheels/*.whl \
    && rm -rf /tmp/wheels /tmp/requirements-runtime.lock

USER 10001:10001
WORKDIR /app
EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=3s --start-period=3s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/api/v1/health', timeout=2).read()"]

CMD ["detection-platform", "serve", "--host", "0.0.0.0", "--port", "8080"]
