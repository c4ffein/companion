# Companion - Development Notes

## After modifying `src/companion.py`

Always run these two commands in order after making changes:

1. `make check` — formats, lints, and runs tests
2. `make build` — rebuilds `companion.py` with inlined PDF.js

Do not consider work complete until both pass.
