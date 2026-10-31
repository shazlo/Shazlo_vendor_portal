FROM python:3.12-slim AS builder
WORKDIR /build
COPY pyproject.toml ./
COPY identity_api ./identity_api
RUN pip wheel --no-cache-dir --wheel-dir /wheels .

FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
RUN useradd --system --uid 10001 --no-create-home app
COPY --from=builder /wheels /wheels
RUN pip install --no-cache-dir /wheels/*.whl && rm -rf /wheels
WORKDIR /app
# Lets `alembic upgrade head` run in the container; migrations ship inside the package.
COPY alembic.ini ./
USER app
EXPOSE 8001
HEALTHCHECK --interval=10s --timeout=3s --retries=5 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8001/health')"
CMD ["uvicorn", "identity_api.main:app", "--host", "0.0.0.0", "--port", "8001"]
