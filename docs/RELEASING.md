# Releasing ReproTrace

Releases go to PyPI from GitHub Actions with Trusted Publishing: PyPI trusts this
repository's `release.yml` workflow directly, so no PyPI password or API token is stored in
GitHub or anywhere else.

## One-time setup

1. **Accounts.** Create accounts on [pypi.org](https://pypi.org) and
   [test.pypi.org](https://test.pypi.org) (they are separate) and turn on two-factor
   authentication on both.
2. **Pending publishers.** On each site, open *Your account > Publishing > Add a new pending
   publisher > GitHub* and enter:

   | Field | PyPI | TestPyPI |
   |---|---|---|
   | PyPI project name | `reprotrace` | `reprotrace` |
   | Owner | `Ketan-Verma21` | `Ketan-Verma21` |
   | Repository name | `ReproTrace` | `ReproTrace` |
   | Workflow name | `release.yml` | `release.yml` |
   | Environment name | `pypi` | `testpypi` |

   A pending publisher reserves the name; the project is created by the first upload.
3. **GitHub environments.** In the repository, *Settings > Environments*, create `pypi` and
   `testpypi`. For `pypi`, add yourself under *Required reviewers*, so every real upload
   waits for your approval.

## Trial run on TestPyPI

*Actions > release > Run workflow* builds the package, checks it (`twine check`, a clean
install, `reprotrace version`) and uploads it to TestPyPI. Try the result:

```text
pipx install --index-url https://test.pypi.org/simple/ \
  --pip-args="--extra-index-url https://pypi.org/simple/" reprotrace
reprotrace version
```

The extra index is needed because the dependencies (Typer, Pydantic) live on the real PyPI.
TestPyPI accepts each version once; rerunning the trial skips files that already exist.

## Each release

1. Set the new version in `pyproject.toml` and `src/reprotrace/__init__.py`, and add a
   section to `CHANGELOG.md`.
2. `pytest && ruff check .`, commit and push; wait for the `ci` workflow to pass.
3. Tag and create the GitHub release (the tag must be `v` plus the version, or the workflow
   stops before uploading; the example is for 0.1.2):

   ```text
   git tag -a v0.1.2 -m "ReproTrace v0.1.2"
   git push origin v0.1.2
   gh release create v0.1.2 --title "ReproTrace v0.1.2" --notes-file CHANGELOG.md
   ```

4. Publishing the release starts `release.yml`; approve the `pypi` deployment when GitHub
   asks. A minute later `pipx install reprotrace` installs the new version.

A version number can never be uploaded to PyPI twice, even after deleting it. If something
is wrong with a release, fix it and release the next patch version.
