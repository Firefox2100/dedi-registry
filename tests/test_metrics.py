"""
Tests for the Prometheus middleware, driven directly with a small Starlette app so
the failure paths can be provoked.
"""

import httpx
import pytest
from httpx import ASGITransport

from starlette.applications import Starlette
from starlette.responses import PlainTextResponse, StreamingResponse
from starlette.routing import Route

from dedi_registry.etc.metrics import REGISTRY as PROMETHEUS, PrometheusMetricsMiddleware


def sample(name: str, **labels) -> float:
    value = PROMETHEUS.get_sample_value(name, labels)
    return 0.0 if value is None else value


async def plain(request):
    return PlainTextResponse('hello')


async def echo(request):
    return PlainTextResponse(await request.body())


async def streamed(request):
    async def chunks():
        yield b'one,'
        yield b'two'

    return StreamingResponse(chunks())


async def events(request):
    async def chunks():
        yield b'data: tick\n\n'

    return StreamingResponse(chunks(), media_type='text/event-stream')


async def broken(request):
    raise RuntimeError('boom')


async def metrics_page(request):
    return PlainTextResponse('# metrics')


@pytest.fixture
async def client():
    app = Starlette(routes=[
        Route('/plain', plain),
        Route('/echo', echo, methods=['POST']),
        Route('/streamed', streamed),
        Route('/events', events),
        Route('/broken', broken),
        Route('/metrics', metrics_page),
        Route('/items/{item_id}', plain),
    ])
    app.add_middleware(PrometheusMetricsMiddleware)

    transport = ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url='http://test') as client:
        yield client


async def test_requests_are_counted(client):
    labels = {'method': 'GET', 'endpoint': '/plain', 'status_code': '200'}
    before = sample('http_requests_total', **labels)

    await client.get('/plain')
    await client.get('/plain')

    assert sample('http_requests_total', **labels) == before + 2


async def test_routes_are_labelled_by_template_not_by_value(client):
    await client.get('/items/1')
    await client.get('/items/2')

    assert sample(
        'http_requests_total', method='GET', endpoint='/items/{item_id}', status_code='200',
    ) >= 2
    assert sample(
        'http_requests_total', method='GET', endpoint='/items/1', status_code='200',
    ) == 0


async def test_request_and_response_sizes_are_observed(client):
    request_labels = {'method': 'POST', 'endpoint': '/echo'}
    response_labels = {**request_labels, 'status_code': '200'}
    request_before = sample('http_request_size_sum', **request_labels)
    response_before = sample('http_response_size_sum', **response_labels)

    await client.post('/echo', content=b'x' * 40)

    assert sample('http_request_size_sum', **request_labels) == request_before + 40
    assert sample('http_response_size_sum', **response_labels) == response_before + 40


async def test_streaming_body_is_still_delivered(client):
    response = await client.get('/streamed')

    assert response.text == 'one,two'
    assert sample(
        'http_response_size_sum', method='GET', endpoint='/streamed', status_code='200',
    ) >= len('one,two')


async def test_server_sent_events_are_not_measured(client):
    response = await client.get('/events')

    assert 'tick' in response.text
    assert sample(
        'http_response_size_count', method='GET', endpoint='/events', status_code='200',
    ) == 0
    # The request is still counted
    assert sample(
        'http_requests_total', method='GET', endpoint='/events', status_code='200',
    ) == 1


async def test_failures_are_propagated(client):
    response = await client.get('/broken')

    assert response.status_code == 500


async def test_invalid_content_length_does_not_break_the_request(client):
    response = await client.get('/plain', headers={'Content-Length': 'abc'})

    # The middleware logs and carries on; the server itself may refuse the header
    assert response.status_code in (200, 400)


async def test_metrics_endpoint_is_not_measured(client):
    await client.get('/metrics')

    assert sample(
        'http_requests_total', method='GET', endpoint='/metrics', status_code='200',
    ) == 0
