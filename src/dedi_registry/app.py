import secrets
import importlib.resources as pkg_resources
from contextlib import asynccontextmanager
import uvicorn
from starlette.middleware.sessions import SessionMiddleware
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import Response
from starlette.exceptions import HTTPException
from fastapi.exception_handlers import http_exception_handler as fastapi_http_exception_handler
from asgi_csrf import asgi_csrf
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from dedi_registry import __version__ as dedi_registry_version
from dedi_registry.etc.consts import LOGGER, CONFIG
from dedi_registry.etc.metrics import REGISTRY, PrometheusMetricsMiddleware
from dedi_registry.database import get_active_db
from dedi_registry.router import admin_router, api_router, ui_router
from dedi_registry.router.util import TEMPLATES, build_nav_links


@asynccontextmanager
async def lifespan(_: FastAPI):
    """
    Lifespan context manager for the FastAPI application.
    :param _: The FastAPI application instance.
    """
    db = get_active_db()

    try:
        LOGGER.info('Starting Decentralised Discovery Network Registry application...')

        await db.init()
        LOGGER.info('Database connection established.')

        LOGGER.info('Application startup complete.')
        yield
    except Exception as e:
        LOGGER.exception('Error during application startup: %s', e)
        raise
    finally:
        LOGGER.info('Stopping Decentralised Discovery Network Registry application...')
        await db.close()

        LOGGER.info('Application shutdown complete.')


def create_app() -> FastAPI:
    """
    Create and configure the FastAPI application.
    :return: The configured FastAPI application instance.
    """
    app = FastAPI(
        title='Decentralised Discovery Network Registry',
        version=dedi_registry_version,
        description='A network registry for Decentralised Discovery Gateway systems to '
                    'report the networks for public finding.',
        contact={
            'name': 'Firefox2100',
            'url': 'https://github.com/Firefox2100',
            'email': 'wangyunze16@gmail.com',
        },
        license_info={
            'name': 'GNU GENERAL PUBLIC LICENSE v3.0',
            'url': 'https://github.com/Firefox2100/dedi-registry/blob/main/LICENSE',
        },
        openapi_tags=[
            {
                'name': 'Admin',
                'description': 'Endpoints for administrators to manage the registry.'
            },
            {
                'name': 'API',
                'description': 'Endpoints for other DDG services to interact with the registry.',
            },
            {
                'name': 'UI',
                'description': 'Endpoints for the web user interface.',
            },
        ],
        lifespan=lifespan,
    )

    @app.middleware('http')
    async def disable_cors_for_api(request, call_next):
        if request.url.path.startswith('/api'):
            request.scope['cors_exempt'] = True

        response = await call_next(request)
        if request.url.path.startswith('/api'):
            response.headers['Access-Control-Allow-Origin'] = '*'

        return response

    @app.middleware('http')
    async def csp_headers(request, call_next):
        nonce = secrets.token_urlsafe(16)
        request.state.csp_nonce = nonce

        response = await call_next(request)

        if any([
            request.url.path.startswith('/static/'),
            request.url.path.startswith('/api/'),
            request.url.path.startswith('/docs'),
            request.url.path.startswith('/redoc'),
        ]):
            return response

        # Build a strict policy (adjust as you add features)
        directives = [
            "default-src 'self'",
            "base-uri 'self'",
            "object-src 'none'",
            "frame-ancestors 'self'",
            "form-action 'self'",
            "img-src 'self' data:",
            "font-src 'self'",
            "style-src 'self'",
            f"script-src 'self' 'nonce-{nonce}'",
        ]

        if CONFIG.use_https:
            # Upgrading on a plain HTTP deployment would break every sub-resource
            directives.append("upgrade-insecure-requests")

        policy = "; ".join(directives)

        response.headers['Content-Security-Policy'] = policy
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'

        return response

    app.add_middleware(
        SessionMiddleware,
        secret_key=CONFIG.secret_key,
        same_site='lax',
        https_only=CONFIG.use_https,
    )

    app.add_middleware(PrometheusMetricsMiddleware)

    # Added last so it is the outermost layer: it answers preflight requests itself and
    # puts its headers on responses produced by every other middleware, errors included
    app.add_middleware(
        CORSMiddleware,
        allow_origins=set(CONFIG.allow_origins) or (),
        allow_credentials=True,
        allow_methods=('GET', 'POST', 'PATCH', 'PUT', 'DELETE', 'OPTIONS'),
        allow_headers=(
            'Authorization',
            'Content-Type',
            'Accept',
            'X-Requested-With',
        ),
    )

    app.include_router(admin_router)
    app.include_router(api_router)
    app.include_router(ui_router)

    static_file_path = pkg_resources.files('dedi_registry.data') / 'static'
    app.mount('/static', StaticFiles(directory=str(static_file_path)), name='static')

    @app.get('/health', include_in_schema=False)
    async def health_check():
        """
        Health check endpoint to verify the application is running.
        :return: A JSON response indicating the application status.
        """
        return {'status': 'ok'}

    @app.get('/metrics', include_in_schema=False)
    async def export_metrics():
        """
        Endpoint to export Prometheus metrics.
        :return: Metrics in Prometheus format.
        """
        return Response(
            content=generate_latest(REGISTRY),
            media_type=CONTENT_TYPE_LATEST,
        )

    @app.exception_handler(HTTPException)
    async def http_exception_handler(request, exc):
        LOGGER.error('HTTP Exception: %s', exc)

        if request.url.path.startswith('/api'):
            # Do not use HTML responses for API endpoints, pass it to FastAPI's default handler
            return await fastapi_http_exception_handler(request, exc)

        # For UI endpoints, build navigation links and render an error page
        db = get_active_db()
        nav_links = await build_nav_links(request, db)
        context = {
            'page_title': f'{exc.status_code} Error | Decentralised Discovery Network Registry',
            'detail': getattr(exc, 'detail', None),
            'nav_links': nav_links,
            'return_url': '/',
            'return_label': 'Back to Home',
        }

        if exc.status_code == 404:
            return TEMPLATES.TemplateResponse(
                request,
                '404.html',
                context=context,
                status_code=404
            )

        return TEMPLATES.TemplateResponse(
            request,
            '500.html',
            context=context,
            status_code=exc.status_code
        )

    def skip_paths(scope):
        return scope['path'].startswith('/api/')

    app = asgi_csrf(
        app,
        signing_secret=CONFIG.secret_key,
        always_protect={'/admin/login'},
        cookie_secure=CONFIG.use_https,
        skip_if_scope=skip_paths,
    )

    return app


def main():
    """
    Main entry point for the application
    :return:
    """
    app = create_app()

    # Remove the logging handler added in the application code
    # This makes the log propagate to uvicorn's logging configuration
    if LOGGER.hasHandlers():
        for h in LOGGER.handlers[:]:
            LOGGER.removeHandler(h)

    uvicorn.run(
        app,
        host=CONFIG.host,
        port=CONFIG.port,
        log_config={
            'version': 1,
            'disable_existing_loggers': False,
            'formatters': {
                'default': {
                    "()": "uvicorn.logging.DefaultFormatter",
                    'fmt': '[%(asctime)s] [%(process)d] [%(levelname)s]: %(message)s',
                    'datefmt': '%Y-%m-%d %H:%M:%S %z',
                },
                'access': {
                    '()': 'uvicorn.logging.AccessFormatter',
                    'fmt': '%(levelprefix)s %(client_addr)s - '
                           '"%(request_line)s" %(status_code)s',
                },
            },
            'handlers': {
                'default': {
                    'formatter': 'default',
                    'class': 'logging.StreamHandler',
                    'stream': 'ext://sys.stderr',
                },
                'access': {
                    'formatter': 'access',
                    'class': 'logging.StreamHandler',
                    'stream': 'ext://sys.stdout',
                },
            },
            'loggers': {
                'uvicorn': {
                    'handlers': ['default'],
                    'level': 'INFO',
                    'propagate': False,
                },
                'uvicorn.error': {
                    'handlers': ['default'],
                    'level': 'INFO',
                    'propagate': False,
                },
                'uvicorn.access': {
                    'handlers': ['access'],
                    'level': 'INFO',
                    'propagate': False,
                },
            },
            'root': {
                'handlers': ['default'],
                'level': CONFIG.logging_level.upper(),  # pylint: disable=no-member
            },
        }
    )


if __name__ == '__main__':
    main()
