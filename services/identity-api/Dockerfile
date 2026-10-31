# Build from the repository root: the image includes packages/py-auth.
#   docker build -f services/identity-api/Dockerfile -t identity-api .
FROM python:3.12-slim AS builder
WORKDIR /build
COPY packages/py-auth ./packages/py-auth
COPY services/identity-api/pyproject.toml ./services/identity-api/
COPY services/identity-api/identity_api ./services/identity-api/identity_api
# Both are given as paths, so identity-api's `shazlo-auth` requirement is met by the local copy.
RUN pip wheel --no-cache-dir --wheel-dir /wheels './packages/py-auth[fastapi]' ./services/identity-api

FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
RUN useradd --system --uid 10001 --no-create-home app
COPY --from=builder /wheels /wheels
RUN pip install --no-cache-dir /wheels/*.whl && rm -rf /wheels
WORKDIR /app
# Lets `alembic upgrade head` run in the container; migrations ship inside the package.
COPY services/identity-api/alembic.ini ./
USER app
EXPOSE 8001
HEALTHCHECK --interval=10s --timeout=3s --retries=5 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8001/health')"
CMD ["uvicorn", "identity_api.main:app", "--host", "0.0.0.0", "--port", "8001"]
