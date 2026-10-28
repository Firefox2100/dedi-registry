import pytest
from asgi_lifespan import LifespanManager

from dedi_registry.app import create_app


@pytest.fixture(scope='session')
async def app_manager():
    """
    One running application for the whole session.

    The database and cache are process-wide singletons that the application closes on
    shutdown, so every test module must share a single lifespan rather than start its own.
    """
    async with LifespanManager(create_app()) as manager:
        yield manager
