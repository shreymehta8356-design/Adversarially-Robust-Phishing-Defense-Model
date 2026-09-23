# PhishGuard as a Hugging Face Space (Docker SDK, free CPU tier: 2 vCPU, 16 GB).
#
# Copy this file to the root of a new Docker Space together with the whole
# repository, or point the Space at the GitHub repository and set
# "Dockerfile path" to deploy/huggingface-space/Dockerfile. Spaces expose port
# 7860 and run as user 1000 with a writable home directory.
FROM python:3.11-slim AS builder
WORKDIR /src
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir --prefix=/install .

FROM python:3.11-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONHASHSEED=0 \
    PATH="/install/bin:$PATH" PYTHONPATH="/install/lib/python3.11/site-packages" \
    PG_ENVIRONMENT=prod PG_LOG_FORMAT=json PG_ARTIFACTS_DIR=/home/user/data \
    PG_BOOTSTRAP_N=9000 PG_API_WORKERS=1 PG_CORS_ORIGINS='[]' PORT=7860
RUN useradd -m -u 1000 user
COPY --from=builder /install /install
COPY --chown=user docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh && mkdir -p /home/user/data && chown -R user /home/user
USER user
WORKDIR /home/user
EXPOSE 7860
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["serve"]
