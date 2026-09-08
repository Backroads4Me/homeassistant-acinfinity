"""Control writes preserve unrelated settings from the selected mode record."""

from copy import deepcopy
from unittest.mock import AsyncMock

import pytest

from custom_components.ac_infinity.client import (
    ADD_DEV_MODE_KEYS,
    APP_VERSION,
    API_URL_ADD_DEV_MODE,
    API_URL_GET_DEV_MODE_SETTING,
    ACInfinityClient,
    ACInfinityClientInvalidAuth,
    ACInfinityClientCannotConnect,
    ACInfinityClientRecoveryFailed,
    ACInfinityClientRequestFailed,
    build_sign,
)
from custom_components.ac_infinity.core import ACInfinityService


@pytest.mark.asyncio
@pytest.mark.parametrize('minimum,maximum,nested_maximum', [(3, 10, 6), (0, 6, 10)])
async def test_temperature_write_preserves_mode_speed_limits(
    minimum, maximum, nested_maximum
):
    client = ACInfinityClient('http://example.invalid', 'test@example.invalid', 'test')
    client._user_id = 'test-user'
    current = {
        'devId': 'test-controller',
        'externalPort': 0,
        'atType': 3,
        'offSpead': minimum,
        'onSpead': maximum,
        'devHt': 38,
        'devHtf': 100,
        'devSetting': {'offSpead': 0, 'onSpead': nested_maximum},
    }
    snapshot = deepcopy(current)
    post = AsyncMock(side_effect=[{'data': current}, {'code': 200}])
    client._ACInfinityClient__post = post

    await client.update_device_controls(
        'test-controller', 1, {'devHt': 41, 'devHtf': 105}, 11
    )

    read, write = post.call_args_list
    assert read.args[0] == API_URL_GET_DEV_MODE_SETTING
    assert read.args[1]['port'] == 1
    assert write.args[0] == API_URL_ADD_DEV_MODE
    payload = write.args[1]
    assert payload['externalPort'] == '1'
    assert payload['offSpead'] == str(minimum)
    assert payload['onSpead'] == str(maximum)
    assert payload['devHt'] == '41'
    assert payload['devHtf'] == '105'
    assert payload['atType'] == '3'
    assert current == snapshot


@pytest.mark.asyncio
async def test_speed_limit_write_preserves_temperature_and_mode():
    client = ACInfinityClient('http://example.invalid', 'test@example.invalid', 'test')
    client._user_id = 'test-user'
    post = AsyncMock(side_effect=[{'data': {
        'devId': 'test-controller', 'externalPort': 0, 'atType': 3,
        'offSpead': 0, 'onSpead': 6, 'devHt': 38, 'devHtf': 100,
        'activeHt': 1, 'devSetting': {'offSpead': 0, 'onSpead': 10},
    }}, {'code': 200}])
    client._ACInfinityClient__post = post

    await client.update_device_controls(
        'test-controller', 1, {'offSpead': 3, 'onSpead': 10}, 11
    )

    payload = post.call_args_list[1].args[1]
    assert payload['offSpead'] == '3'
    assert payload['onSpead'] == '10'
    assert payload['devHt'] == '38'
    assert payload['devHtf'] == '100'
    assert payload['atType'] == '3'
    assert payload['activeHt'] == '1'


def _minimal_record():
    return {
        'devId': 'test-controller',
        'externalPort': 1,
        'atType': 3,
        'offSpead': 0,
        'onSpead': 6,
        'devHt': 38,
        'devHtf': 100,
        'devSetting': {},
    }


@pytest.mark.asyncio
@pytest.mark.parametrize(
    'field,sentinel',
    [('insidePort', '255'), ('outsidePort', '255'), ('insideType', '15'),
     ('outsideType', '15'), ('settingModeAi', '1'), ('targetTempFAi', '32')],
)
async def test_null_binding_field_uses_the_sentinel_not_zero(field, sentinel):
    """A field the controller reports as null means the same as an omitted one.

    Port and type 0 name a real external sensor binding; 255 and 15 mean
    nothing is bound.
    """
    client = ACInfinityClient('http://example.invalid', 'test@example.invalid', 'test')
    client._user_id = 'test-user'
    record = _minimal_record()
    record[field] = None
    post = AsyncMock(side_effect=[{'data': record}, {'code': 200}])
    client._ACInfinityClient__post = post

    await client.update_device_controls('test-controller', 1, {'devHt': 41}, 11)

    _, write = post.call_args_list
    assert write.args[1][field] == sentinel


@pytest.mark.asyncio
async def test_expired_session_logs_in_again_and_retries_once():
    """The access token expires; the app refreshes on a 403 and retries."""
    client = ACInfinityClient('http://example.invalid', 'test@example.invalid', 'test')
    client._user_id = 'test-user'
    client._access_token = 'stale-token'
    client._secret_id = 'stale-secret'
    client._request_app = 'stale-request-app'

    post = AsyncMock(side_effect=[
        {'data': _minimal_record()},
        ACInfinityClientRequestFailed({'msg': 'Login Expired Please login again!', 'code': 403}),
        {'code': 200},
    ])
    client._ACInfinityClient__post = post

    async def _relogin():
        client._access_token = 'fresh-token'
        client._secret_id = 'fresh-secret'
        client._request_app = 'fresh-request-app'

    login = AsyncMock(side_effect=_relogin)
    client.login = login

    await client.update_device_controls('test-controller', 1, {'devHt': 41}, 11)

    assert login.await_count == 1
    assert post.await_count == 3

    rejected, retried = post.call_args_list[1], post.call_args_list[2]

    # Every signing input must come from the new session. Asserting only that
    # the signature changed would pass an implementation that refreshed the
    # token while still signing with the stale secret.
    for headers, token, secret, request_app in (
        (rejected.args[2], 'stale-token', 'stale-secret', 'stale-request-app'),
        (retried.args[2], 'fresh-token', 'fresh-secret', 'fresh-request-app'),
    ):
        assert headers['token'] == token
        assert headers['requestApp'] == request_app
        assert headers['sign'] == build_sign(
            token, APP_VERSION, secret, request_app, headers['requestId']
        )

    assert retried.args[0] == rejected.args[0]
    assert retried.args[1] == rejected.args[1]
    assert retried.args[2]['devType'] == '11'


@pytest.mark.asyncio
async def test_a_non_auth_failure_is_not_retried():
    client = ACInfinityClient('http://example.invalid', 'test@example.invalid', 'test')
    client._user_id = 'test-user'
    post = AsyncMock(side_effect=[
        {'data': _minimal_record()},
        ACInfinityClientRequestFailed({'msg': 'Data saving failed', 'code': 999999}),
    ])
    client._ACInfinityClient__post = post
    client.login = AsyncMock()

    with pytest.raises(ACInfinityClientRequestFailed):
        await client.update_device_controls('test-controller', 1, {'devHt': 41}, 11)

    assert client.login.await_count == 0


@pytest.mark.asyncio
async def test_a_second_rejection_is_terminal_and_logs_in_only_once():
    """The service retries a failed write five times.

    Raising the request failure again after a recovery attempt would turn one
    failed write into five password logins against a plaintext API.
    """
    client = ACInfinityClient('http://example.invalid', 'test@example.invalid', 'test')
    client._user_id = 'test-user'
    expired = ACInfinityClientRequestFailed({'msg': 'Login Expired', 'code': 403})
    post = AsyncMock(side_effect=[{'data': _minimal_record()}, expired, expired])
    client._ACInfinityClient__post = post
    client.login = AsyncMock()

    with pytest.raises(ACInfinityClientInvalidAuth):
        await client.update_device_controls('test-controller', 1, {'devHt': 41}, 11)

    assert client.login.await_count == 1


@pytest.mark.asyncio
@pytest.mark.parametrize('top,nested,expected', [(2, 4, '2'), (2, None, '2'), (None, 4, '4'), (None, None, '255')])
async def test_a_null_top_level_field_does_not_hide_a_nested_value(top, nested, expected):
    """A null says nothing about the field, so the nested value still applies."""
    client = ACInfinityClient('http://example.invalid', 'test@example.invalid', 'test')
    client._user_id = 'test-user'
    record = _minimal_record()
    record['insidePort'] = top
    record['devSetting'] = {'insidePort': nested}
    post = AsyncMock(side_effect=[{'data': record}, {'code': 200}])
    client._ACInfinityClient__post = post

    await client.update_device_controls('test-controller', 1, {'devHt': 41}, 11)

    _, write = post.call_args_list
    assert write.args[1]['insidePort'] == expected


@pytest.mark.asyncio
@pytest.mark.parametrize(
    'record_value,expected',
    [('AA:BB:CC:DD:EE:FF', 'AA:BB:CC:DD:EE:FF'), ('', ''), (None, ''), ('missing', '')],
)
async def test_dev_mac_addr_present_and_defaults_empty(record_value, expected):
    """The app sends this field empty; a value the controller reports is kept."""
    client = ACInfinityClient('http://example.invalid', 'test@example.invalid', 'test')
    client._user_id = 'test-user'
    record = _minimal_record()
    if record_value != 'missing':
        record['devMacAddr'] = record_value
    post = AsyncMock(side_effect=[{'data': record}, {'code': 200}])
    client._ACInfinityClient__post = post

    await client.update_device_controls('test-controller', 1, {'devHt': 41}, 11)

    _, write = post.call_args_list
    assert write.args[1]['devMacAddr'] == expected
    assert set(write.args[1]) == set(ADD_DEV_MODE_KEYS)


@pytest.mark.asyncio
@pytest.mark.parametrize('stage', ['login', 'retry'])
@pytest.mark.parametrize('failure', [
    ACInfinityClientCannotConnect('synthetic failure'),
    TimeoutError('synthetic timeout'),
    ACInfinityClientRequestFailed({'code': 999999}),
])
async def test_service_recovery_failure_does_not_restart_operation(mocker, stage, failure):
    client = ACInfinityClient('http://example.invalid', 'test@example.invalid', 'test')
    client._user_id = 'test-user'
    rejected = ACInfinityClientRequestFailed({'code': 403})
    responses = [{'data': _minimal_record()}, rejected]
    if stage == 'retry':
        responses.append(failure)
    post = AsyncMock(side_effect=responses)
    client._ACInfinityClient__post = post
    client.login = AsyncMock(side_effect=failure if stage == 'login' else None)
    sleep = mocker.patch('custom_components.ac_infinity.core.asyncio.sleep', new_callable=AsyncMock)

    with pytest.raises(ACInfinityClientRecoveryFailed) as error:
        await ACInfinityService(client)._ACInfinityService__update_device_controls(
            'test-controller', 1, {'devHt': 41}, 11
        )

    assert error.value.__cause__ is failure
    client.login.assert_awaited_once()
    assert post.await_count == (2 if stage == 'login' else 3)
    sleep.assert_not_awaited()
