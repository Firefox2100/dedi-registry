"""
Unit tests for helpers that decide where a user may be redirected and which
navigation links they see. Redirect handling is security relevant, so the edge
cases are spelled out one by one.
"""

import pytest

from dedi_registry.router.util import sanitise_next_url


@pytest.mark.parametrize('value', [None, ''])
def test_missing_next_falls_back_to_default(value):
    assert sanitise_next_url(value) == '/'
    assert sanitise_next_url(value, default='/elsewhere') == '/elsewhere'


@pytest.mark.parametrize('value', [
    'https://evil.example/',
    'http://evil.example/networks',
    '//evil.example/networks',
    'javascript:alert(1)',
    'ftp://evil.example',
])
def test_absolute_and_scheme_relative_urls_are_refused(value):
    assert sanitise_next_url(value) == '/'


@pytest.mark.parametrize('value', [
    '/not/a/known/page',
    '/admin/../../etc/passwd',
    '/admin/networks/not-a-uuid/approve-everything',
])
def test_unknown_destinations_are_refused(value):
    assert sanitise_next_url(value, default='/safe') == '/safe'


@pytest.mark.parametrize('value', ['/', '/networks', '/admin'])
def test_known_pages_are_kept(value):
    assert sanitise_next_url(value, default='/safe') == value


def test_query_is_kept_and_fragment_dropped():
    assert sanitise_next_url('/networks?status=pending#top') == '/networks?status=pending'


def test_path_is_normalised_before_checking():
    assert sanitise_next_url('/networks/../admin') == '/admin'
    assert sanitise_next_url('/networks/./') == '/networks'


def test_network_detail_pages_are_allowed():
    path = '/networks/3f9a1c6e-7c52-4b2e-9d8a-0a1b2c3d4e5f'

    assert sanitise_next_url(path) == path
