# Contribute

Thank you for considering contributing to API-Key Manager!

## Report issues

Issue tracker: <https://github.com/csgroup-oss/apikey-manager/>

Please check that a similar issue does not already exist and include the
following information in your post:

- Describe what you expected to happen.
- If possible, include a [minimal reproducible
  example](https://stackoverflow.com/help/minimal-reproducible-example)
  to help us identify the issue. This also helps check that the issue
  is not with your own code.
- Describe what actually happened. Include the full traceback if there
  was an exception.
- List your Python and apikeymanager versions. If possible, check if this
  issue is already fixed in the latest releases or the latest code in
  the repository.

## Submit patches

If you intend to contribute to eodag source code:

```bash
git clone https://github.com/csgroup-oss/apikey-manager.git
cd apikey-manager
python -m pip install -e .[dev] --no-cache-dir
pre-commit install
```

We use `pre-commit` to run a suite of linters, formatters and pre-commit
hooks (`black`, `isort`, `flake8`) to ensure the code base is
homogeneously formatted and easier to read. It's important that you
install it, since we run the exact same hooks in the Continuous
Integration.

## Release of APIKeyManager

Releases are made by tagging a commit on the master branch. APIKeyManager
version is then automatically updated using
`setuptools_scm` [WIP].To make a new release,

- Ensure you correctly updated
  `README.md` and
  `CHANGES.md` (and occasionally, also
  `NOTICE.md` - in case a new dependency is
  added).
- Check that the fallback version string in
  `pyproject.toml` (the variable
  `fallback_version`) is correctly
  updated to the new TAG
- Push your local master branch to remote.
- Tag the commit that represents the state of the release with a
  message. For example, for version 1.0, do this:
  `git tag -a v1.0 -m 'version 1.0'`
- Push the tags to github: `git push
--tags`.

### Create and publish the Docker image

We'll need to push the image to a docker registry.

```bash
# Login
docker login <your-registry>
# Example: docker login 643vlk6z.gra7.container-registry.ovh.net

# Tag the image for your registry
docker build -t 643vlk6z.gra7.container-registry.ovh.net/metis/apikeymanager:<version> .

# Push
docker push 643vlk6z.gra7.container-registry.ovh.net/metis/apikeymanager:<version>
```
