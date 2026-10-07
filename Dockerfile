FROM python:3.12-slim

# hpack provides ONLY the mature Huffman string primitive
# (hpack.huffman_table.decode_huffman) and, for the test suite, the
# standard encoder used to generate samples.  The auditor never hands a
# whole header block to a ready-made HPACK decoder; if hpack is absent it
# falls back to its embedded RFC 7541 Appendix B table decoder.
RUN pip install --no-cache-dir "hpack>=4,<5"

WORKDIR /app
COPY h2audit.py /app/h2audit.py
COPY tests/ /app/tests/

ENTRYPOINT ["python3", "/app/h2audit.py"]
