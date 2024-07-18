FROM amd64/python:3.12-alpine as build

# Add non root user
RUN addgroup -S app && adduser app -S -G app && chown app /home/app

USER app

ENV PATH=$PATH:/home/app/.local/bin
ARG SETUPTOOLS_SCM_PRETEND_VERSION
RUN test -n "$SETUPTOOLS_SCM_PRETEND_VERSION" || \
    ( echo -e "\n'--build-arg SETUPTOOLS_SCM_PRETEND_VERSION=<version>' is mandatory !" && exit 2 )

WORKDIR /home/app/

COPY --chown=app:app pyproject.toml   .
COPY --chown=app:app setup.py         .
COPY --chown=app:app app/__init__.py  app/
COPY --chown=app:app log_config.yaml  .

# Install dependencies and create the app/_version.py file with setuptools_scm
USER root
RUN pip install --root-user-action=ignore --no-cache-dir .[postgres]
RUN chown app:app app/_version.py

FROM build as test
ARG TEST_COMMAND=tox
ARG TEST_ENABLED=false
RUN [ "$TEST_ENABLED" = "false" ] && echo "skipping tests" || eval "$TEST_COMMAND"

FROM build as ship
WORKDIR /home/app/
COPY --chown=app:app app/            app/
USER app
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--log-config", "log_config.yaml"]
