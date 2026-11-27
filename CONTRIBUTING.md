# Contributing to AMES

Thanks for your interest. Contributions of every size are welcome, from a typo fix to a new feature.

## Ways to help

- Help is especially wanted with new attack vectors in `vectors/`, extra containment checks, and validation reports.
- Look for issues labelled `good first issue` or `help wanted`.
- Report a bug or suggest an idea by opening an issue (templates are provided).
- Improve the docs. If something confused you, it will confuse the next person too.

## Getting set up

```bash
git clone https://github.com/kaymyg/ames.git
cd ames
pip install -r requirements.txt
```

## Running the checks

```bash
python -m pytest -q
```

Please make sure this passes before opening a pull request. CI runs the same checks.

## Pull request workflow

1. Fork the repository and create a branch from the default branch.
2. Keep each pull request focused on one change.
3. Add or update tests when you change behaviour.
4. Describe what you changed and why in the pull request description.
5. Be ready for review comments. Small, quick iterations are normal.

## Security issues

Please do not open a public issue for a vulnerability. See [SECURITY.md](SECURITY.md).

## Code of conduct

By taking part you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## License

By contributing, you agree that your contributions are licensed under the same license as this repository (see [LICENSE](LICENSE)).
