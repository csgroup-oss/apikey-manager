# API Key Manager

## Env vars

| Variable                | Description         | Default value                                                                 |
| ----------------------- | ------------------- | ----------------------------------------------------------------------------- |
| ALLOWED_ORIGIN_REGEX    |                     | `.*(geostorm\.eu\|csgroup\.space)`                                            |
| API_PREFIX              |                     |                                                                               |
| DEBUG                   | Display SQL request | `False`                                                                       |
| API_KEYS_DB_URL         |                     | `sqlite:///./test.db`                                                         |
| API_KEYS_EXPIRE_IN_DAYS |                     | `15`                                                                          |
| API_KEYS_SHOW_ENDPOINTS |                     | `True`                                                                        |
| OAUTH2_METADATA_URL     |                     | `https://auth.p3.csgroup.space/realms/METIS/.well-known/openid-configuration` |

## Developement

### Install development environment

Creating the development environment :

```bash
virtualenv -p python3.11 venv
source venv/bin/activate
```

setuptools allows you to install a package without copying any files to your interpreter directory (e.g. the site-packages directory). This allows you to modify your source code and have the changes take effect without you having to rebuild and reinstall. Here’s how to do it:

```bash
pip install -e .[dev] --no-cache-dir
```

To run precommit rules against all the files

```bash
pre-commit install # Enable precommit
pre-commit run --all-files
```

### Launch test

The execution of the tests is done with `pytest`. It is fully automated, thanks to the use of `pytest-docker` which will automatically start a `timescaledb` container to run the tests.
The launch of the tests is simply done with the following command :

```bash
python -m pytest
```

### Run with uvicorn

```bash
uvicorn app.main:app --host localhost --port 9999 --reload
```

You can check the API docs at [localhost:9999](http://localhost:9999/docs/).

> You can also run a test server for benchmarking purpose :
>
> ```bash
> # Install a simple but efficient http-server
> npm install http-server -g
> # Launch the server
> http-server test/ -p 8999 -s
> # Make some test
> wrk -t6 -c40 http://localhost:9999/teleray_speedtest.csv
> ```

### Run with docker container

Build image

```bash
docker build -t apikeymanager:latest .
```

Use it

```bash
docker run --name apikeymanager --rm \
    -p 8000:8000 \
    apikeymanager:latest
```

You can check the API docs at [localhost:8000](http://localhost:8000/docs).

## Test

Launch two instance (one for the web server, the second for S3 management). Only needed in test because uvicorn runs single threated.

```bash
uvicorn app.main:app --host localhost --port 9998 --reload
uvicorn app.main:app --host localhost --port 9999 --reload
```

## Production

### Create the Docker image

We'll need to push the image to a docker registry.

```bash
# Login
docker login <your-registry>
# Example: docker login 643vlk6z.gra7.container-registry.ovh.net

# Tag the image for your registry
docker build -t 643vlk6z.gra7.container-registry.ovh.net/metis/apikey-manager:<version> .

# Push
docker push 643vlk6z.gra7.container-registry.ovh.net/metis/apikey-manager:<version>
```

### HELM

Create a robot account in the harbor interface to access GeoJson Proxy Image

```bash
kubectl create namespace apikeymanager

kubectl create secret docker-registry regcred --docker-username='xxxxxxx' --docker-password='yyyyyyyyyyy' --docker-server='643vlk6z.gra7.container-registry.ovh.net' --namespace apikeymanager
```

Deploy APIKey Manager

```bash
helm upgrade --install apikeymanager ./deploy/helm/apikeymanager --namespace apikeymanager --values deploy/helm/values.yaml
```
