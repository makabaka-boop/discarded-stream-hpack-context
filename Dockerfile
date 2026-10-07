FROM python:3.11-slim

WORKDIR /app

# Install only the mature Huffman/HPACK primitive dependency. The auditor's
# HPACK block decoder itself is implemented in this repository.
COPY pyproject.toml README.md ./
COPY h2_audit ./h2_audit
RUN pip install --no-cache-dir .

USER 65534:65534

ENTRYPOINT ["h2-hpack-audit"]
CMD ["--help"]
