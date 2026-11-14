# Decentralised Discovery Network Registry

[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=Firefox2100_dedi-registry&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=Firefox2100_dedi-registry) [![Bugs](https://sonarcloud.io/api/project_badges/measure?project=Firefox2100_dedi-registry&metric=bugs)](https://sonarcloud.io/summary/new_code?id=Firefox2100_dedi-registry) [![Coverage](https://sonarcloud.io/api/project_badges/measure?project=Firefox2100_dedi-registry&metric=coverage)](https://sonarcloud.io/summary/new_code?id=Firefox2100_dedi-registry) [![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=Firefox2100_dedi-registry&metric=security_rating)](https://sonarcloud.io/summary/new_code?id=Firefox2100_dedi-registry)

A network registry for Decentralised Discovery Gateway systems to report the networks for public finding.

## Features

This is a simple registry service that allows Decentralised Discovery Gateway systems to register their networks. The gateway servers are running independently, without a place to control what networks are there and how to join or find them. This service fills in the blanks by allowing the nodes running the gateway service to optionally report the network information to the registry, so that the others can easily find and join the networks.

The system offers:

- **Network Registration**: Gateway nodes can register their networks with details such as network name, description, and connection information.
- **Network Discovery**: Users can search and discover registered networks based on various criteria.
- **API Access**: Provides a RESTful API for programmatic access to register and discover
- **Admin Controlling**: An admin may choose to manually approve or automatically approve a network registration. Later, they may decide to reject the registration anyway (which will remove it from the public listing), or ban the network permanently (which bans the registration of the same IP address, domain and user agent in the future).
- **Security on Registration**: To prevent spam and abuse, the registration process includes a hash challenge to be solved by the registering node. The challenge solving function is implemented in the gateway software itself, and SHOULD be implemented by any other software that uses the same protocol stack.
- **Security on Modification**: When modifying the network information, for example by reporting new nodes, change of name or description, etc. the request needs to be signed by a private key. The public key should have been reported during the registration. This also serves as permission control, as it's a network management key, and may be controlled by one or more nodes in the network that was given the permission to manage the network.

## Installation

The software is written in Python and uses the FastAPI framework with Jinja2 for UI rendering. It can be run using Uvicorn.

### Prerequisites

- Python 3.11 or higher
- pip (Python package installer)
- MongoDB 8.0 or higher
- Redis 7.0 or higher

### Installing from code

Ensure you have Python environment setup. We recommend using either a separate conda environment or `venv` or `virtualenv` to create a virtual environment. This way the installation is cleaner and easier to manage.

```bash
git clone https://github.com/Firefox2100/dedi-registry.git
cd dedi-registry
python -m venv .venv
source .venv/bin/activate  # On Windows use `.venv\Scripts\activate`
pip install . # or `pip install -e .` for editable install
```

The software is configured via environment variables. It also can read a `.env` file in a given path, defaulting to `./conf/.env`. The path to that file is configurable via the `DR_ENV_FILE` environment variable.

```bash
cp example.env conf/.env
vim conf/.env  # Edit the configuration as needed
export DR_ENV_FILE=/absolute/path/to/conf/.env  # Optional, if you want to start from a different working directory. You can also keep this in your shell profile for convenience.
```

Assuming you have started the databases as needed and configured them correctly, the service is ready to start. You can start it using Uvicorn:

```bash
uvicorn dedi_registry.asgi:application --host 0.0.0.0 --port 5000 --log-config conf/uvicorn-log.config.yaml
```

Or, the `pip install` earlier should have installed a `dedi-registry` command that is available as long as the Python environment is activated. It listens on `127.0.0.1:5000` unless `DR_HOST` and `DR_PORT` say otherwise:

```bash
dedi-registry
```

Note that this is for convenient startup in self-contained environments. None of the startup parameters are configurable via command line arguments, including worker counts.

### Running with Docker

The software can also be run using Docker. A `Dockerfile` is provided for building the image. A copy of the image is also published on [Docker Hub](https://hub.docker.com/r/firefox2100/dedi-registry). Refer to the documents there for tags and versions.

To build the Docker image locally (assuming already in the project directory):

```bash
docker build -t firefox2100/dedi-registry:local .
```

An example docker compose file is provided in the repository as a starting point. You may need to adjust the environment variables and volume mounts as needed.

## Configuration

The software is configured via environment variables. A sample configuration file is provided as `example.env`. You can copy it to `conf/.env` and edit it as needed. Some security sensitive values are not listed in it, and you should generate them yourself.

| Variable           | Description                                               | Default Value |
|--------------------|-----------------------------------------------------------|---------------|
| DR_ENV_FILE        | Path to the .env file                                     | ./conf/.env   |
| DR_HOST            | Address the `dedi-registry` command binds to              | 127.0.0.1     |
| DR_PORT            | Port the `dedi-registry` command listens on               | 5000          |
| DR_AUTO_APPROVE    | Whether to automatically approve network registrations    | false         |
| DR_ALLOW_ORIGINS   | List of allowed origins for CORS                          | []            |
| DR_DATABASE_DRIVER | Database driver to use (mongo)                            | mongo         |
| DR_MONGODB_HOST    | MongoDB host                                              | localhost     |
| DR_MONGODB_PORT    | MongoDB port                                              | 27017         |
| DR_MONGODB_DB_NAME | MongoDB database name                                     | ddn-registry  |
| DR_CACHE_DRIVER    | Cache driver to use (redis)                               | redis         |
| DR_REDIS_HOST      | Redis host                                                | localhost     |
| DR_REDIS_PORT      | Redis port                                                | 6379          |
| DR_LOGGING_LEVEL   | Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)     | INFO          |
| DR_USE_HTTPS       | Whether the service is behind an HTTPS proxy              | true          |
| DR_ADMIN_USERNAME  | Initial admin username. Using CLI is recommended instead. | None          |
| DR_ADMIN_PASSWORD  | Initial admin password. Using CLI is recommended instead. | None          |

## Licences and Third-Party Libraries

The software itself is licensed under GPLv3.0 or later. See the [LICENSE](LICENSE) file for details.

The software uses several third-party libraries, but does not re-distribute most of them. The ones that are bundled and re-distributed are:

- Bootstrap 5.3.8 (MIT License)

Their licences are included with their respective files or source directories.
