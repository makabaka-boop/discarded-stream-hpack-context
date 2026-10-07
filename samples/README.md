# Sample captures

- `filtered-shared-hpack.bin`: two client-side HEADERS frames. Stream 3 inserts a
  custom dynamic table entry; stream 5 uses indexed dynamic entry 62. Auditing
  with `--discard-stream 3` must hide stream 3 while still resolving stream 5.

Regenerate after changing the sample format:

```bash
PYTHONPATH=. python tools/generate_samples.py
```
