"""Signed control recovery through aiohttp against a synthetic loopback API."""

import hashlib
from urllib.parse import parse_qsl
from unittest.mock import AsyncMock

import pytest
from aiohttp import web

from custom_components.ac_infinity.client import (
    ADD_DEV_MODE_KEYS,
    ACInfinityClient,
    ACInfinityClientInvalidAuth,
    ACInfinityClientRecoveryFailed,
)
from custom_components.ac_infinity.core import ACInfinityService


@pytest.mark.asyncio
@pytest.mark.parametrize('outcome', ['success', 'rejected', 'login_failure', 'retry_failure'])
async def test_signed_control_recovery_transport(mocker, outcome):
    counts = {'read': 0, 'write': 0, 'login': 0}
    bodies = []
    failures = []

    async def handler(request):
        if request.path.endswith('appUserLogin'):
            counts['login'] += 1
            if outcome == 'login_failure':
                return web.Response(status=503)
            return web.json_response({'code': 200, 'data': {
                'appId': 'synthetic-user', 'token': 'new-token',
                'secretId': 'new-secret', 'requestApp': 'new-app',
            }})
        if request.path.endswith('getdevModeSettingList'):
            counts['read'] += 1
            return web.json_response({'code': 200, 'data': {
                'devId': 'synthetic &+=é', 'externalPort': 1, 'devSetting': {},
            }})
        counts['write'] += 1
        body = dict(parse_qsl(await request.text(), keep_blank_values=True))
        bodies.append(body)
        headers = request.headers
        fresh = counts['write'] == 2
        token, secret, app = (
            ('new-token', 'new-secret', 'new-app') if fresh
            else ('old-token', 'old-secret', 'old-app')
        )
        md5 = lambda value: hashlib.md5(value.encode(), usedforsecurity=False).hexdigest()
        expected = md5(md5(token + headers['version']) + md5(secret + app + headers['requestId']))
        # Capture handler checks for assertions in the test coroutine.
        failures.extend(name for name, valid in {
            'path': request.path == '/api/dev/addDevMode',
            'query': not request.query_string,
            'content_type': request.content_type == 'application/x-www-form-urlencoded',
            'fields': set(body) == set(ADD_DEV_MODE_KEYS),
            'empty_mac': body.get('devMacAddr') == '',
            'escaping': body.get('devId') == 'synthetic &+=é',
            'port': body.get('externalPort') == '1',
            'value': body.get('devHt') == '41',
            'controller_type': headers.get('devType') == '11',
            'token': headers.get('token') == token,
            'request_app': headers.get('requestApp') == app,
            'signature': headers.get('sign') == expected,
        }.items() if not valid)
        if fresh and outcome == 'retry_failure':
            return web.Response(status=503)
        return web.json_response({'code': 200 if fresh and outcome == 'success' else 403})

    app = web.Application()
    app.router.add_post('/{path:.*}', handler)
    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    site = web.TCPSite(runner, '127.0.0.1', 0)
    client = None
    try:
        await site.start()
        port = runner.addresses[0][1]
        client = ACInfinityClient(f'http://127.0.0.1:{port}', 'fake@example.invalid', 'synthetic')
        client._user_id = 'synthetic-user'
        client._access_token = 'old-token'
        client._secret_id = 'old-secret'
        client._request_app = 'old-app'
        sleep = mocker.patch('custom_components.ac_infinity.core.asyncio.sleep', new_callable=AsyncMock)
        operation = ACInfinityService(client)._ACInfinityService__update_device_controls(
            'synthetic', 1, {'devHt': 41}, 11
        )
        if outcome == 'success':
            await operation
        else:
            error = ACInfinityClientInvalidAuth if outcome == 'rejected' else ACInfinityClientRecoveryFailed
            with pytest.raises(error):
                await operation
        assert not failures
        assert counts == {'read': 1, 'write': 1 if outcome == 'login_failure' else 2, 'login': 1}
        sleep.assert_not_awaited()
        if len(bodies) == 2:
            assert bodies[0] == bodies[1]
    finally:
        if client is not None:
            await client.close()
        await runner.cleanup()
