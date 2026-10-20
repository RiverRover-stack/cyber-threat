# Contributing
1. Fork and create a feature branch.
2. `pip install -r requirements.txt` and make your change in `src/cyberthreat/`.
3. Add or update tests in `tests/`; run `pytest -q` (no API key needed).
4. If you change behaviour, re-execute the notebook (`jupyter nbconvert --to notebook --execute --inplace ...`) and update `docs/`.
5. Never commit API keys, `.env`, or `chroma_db/`.
6. Open a pull request describing the change and its test evidence.
