"""
Unit tests for the command line interface, with the database replaced by an in-memory fake.

The commands run their own event loop, so they cannot share the database client the
end-to-end tests use; the fake keeps these tests independent of it.
"""

import asyncio
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from dedi_registry.cli.cli import create_cli
from dedi_registry.cli.util import run_async
from dedi_registry.etc.consts import PH


class FakeUsers:
    def __init__(self):
        self.stored = {}

    async def save(self, user):
        self.stored[user.username] = user

    async def get(self, username):
        return self.stored.get(username)

    async def filter(self):
        return list(self.stored.values())

    async def delete(self, username):
        self.stored.pop(username, None)


class FakeDatabase:
    def __init__(self):
        self.users = FakeUsers()


@pytest.fixture
def database():
    fake = FakeDatabase()
    with patch('dedi_registry.cli.user.get_active_db', return_value=fake):
        yield fake


def run(*args, **kwargs):
    return CliRunner().invoke(create_cli(), list(args), **kwargs)


def test_create_user_hashes_the_password(database):
    result = run('user', 'create', 'alice', '--password', 'Correct Horse 1!')

    assert result.exit_code == 0
    assert 'Successfully created new user alice' in result.output

    stored = database.users.stored['alice']
    assert stored.password != 'Correct Horse 1!'
    assert PH.verify(stored.password, 'Correct Horse 1!')


def test_create_user_prompts_for_missing_password(database):
    result = run('user', 'create', 'bob', input='Prompted Pass 1!\nPrompted Pass 1!\n')

    assert result.exit_code == 0
    assert PH.verify(database.users.stored['bob'].password, 'Prompted Pass 1!')


def test_create_user_rejects_empty_prompted_password(database):
    result = run('user', 'create', 'carol', input='\n\n')

    assert 'carol' not in database.users.stored
    assert result.exit_code != 0


def test_list_users_when_empty(database):
    result = run('user', 'list')

    assert result.exit_code == 0
    assert 'No users found' in result.output


def test_list_users(database):
    run('user', 'create', 'alice', '--password', 'pw-one')
    run('user', 'create', 'bob', '--password', 'pw-two')

    result = run('user', 'list')

    assert result.exit_code == 0
    assert 'alice' in result.output
    assert 'bob' in result.output
    # Only usernames are shown, never the stored hashes
    assert 'argon2' not in result.output


def test_delete_user(database):
    run('user', 'create', 'alice', '--password', 'pw-one')

    result = run('user', 'delete', 'alice')

    assert result.exit_code == 0
    assert 'Successfully deleted user alice' in result.output
    assert 'alice' not in database.users.stored


def test_delete_unknown_user_changes_nothing(database):
    run('user', 'create', 'alice', '--password', 'pw-one')

    result = run('user', 'delete', 'nobody')

    assert 'No user found with username nobody' in result.output
    assert list(database.users.stored) == ['alice']


def test_help_lists_the_user_commands():
    result = run('--help')

    assert result.exit_code == 0
    assert 'user' in result.output


class TestRunAsync:
    def test_runs_a_coroutine_to_completion(self):
        @run_async
        async def add(a, b):
            return a + b

        assert add(1, 2) == 3

    async def test_inside_a_running_loop_it_schedules_a_task(self):
        @run_async
        async def add(a, b):
            return a + b

        task = add(1, 2)

        assert isinstance(task, asyncio.Task)
        assert await task == 3

    def test_plain_functions_are_returned_unchanged(self):
        def plain():
            return 'plain'

        assert run_async(plain) is plain
