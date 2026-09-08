import hashlib
import json
import logging
import time
from urllib.parse import urlencode

import aiohttp
import async_timeout
from homeassistant.exceptions import HomeAssistantError

from custom_components.ac_infinity.const import AdvancedSettingsKey, AtType, DeviceControlKey, ModeAndSettingKeys

_LOGGER = logging.getLogger(__name__)

API_URL_LOGIN = "/api/user/appUserLogin"
API_URL_GET_DEVICE_INFO_LIST_ALL = "/api/user/devInfoListAll"
API_URL_GET_DEV_MODE_SETTING = "/api/dev/getdevModeSettingList"
API_URL_ADD_DEV_MODE = "/api/dev/addDevMode"
API_URL_MODE_AND_SETTINGS = "/api/dev/modeAndSetting"
API_URL_GET_DEV_SETTING = "/api/dev/getDevSetting"
API_URL_UPDATE_ADV_SETTING = "/api/dev/updateAdvSetting"

# Version name of the Android build whose signing scheme this client reproduces.
# It is an input to the request signature, so it must match the value sent in
# the version header.
APP_VERSION = "2.0.8"


ADD_DEV_MODE_KEYS: tuple[str, ...] = (
    "acitveTimerOff", "acitveTimerOn", "activeCycleOff", "activeCycleOn",
    "activeHh", "activeHt", "activeHtVpd", "activeHtVpdNums",
    "activeLh", "activeLt", "activeLtVpd", "activeLtVpdNums",
    "atType", "co2FanHighSwitch", "co2FanHighValue", "co2LowSwitch",
    "co2LowValue", "devHh", "devHt", "devHtf",
    "devId", "devLh", "devLt", "devLtf",
    "devMacAddr",
    "ecOrTds", "ecTdsLowSwitchEc", "ecTdsLowSwitchTds", "ecTdsLowValueEcMs",
    "ecTdsLowValueEcUs", "ecTdsLowValueTdsPpm", "ecTdsLowValueTdsPpt", "ecUnit",
    "externalPort", "hTrend", "humidity", "insidePort",
    "insidePortAi", "insideType", "insideTypeAi", "isOpenAutomation",
    "leafTempInside", "masterPort", "modeType", "moistureLowSwitch",
    "moistureLowValue", "offSpead", "onSelfSpead", "onSpead",
    "onlyUpdateSpeed", "outsidePort", "outsidePortAi", "outsideType",
    "outsideTypeAi", "phHighSwitch", "phHighValue", "phLowSwitch",
    "phLowValue", "schedEndtTime", "schedStartTime", "settingMode",
    "settingModeAi", "speak", "surplus", "tTrend",
    "targetHumi", "targetHumiAi", "targetHumiSwitch", "targetHumiSwitchAi",
    "targetTSwitch", "targetTSwitchAi", "targetTemp", "targetTempAi",
    "targetTempF", "targetTempFAi", "targetVpd", "targetVpdAi",
    "targetVpdSwitch", "targetVpdSwitchAi", "tdsUnit", "temperature",
    "temperatureF", "trend", "unit", "vpdSettingMode",
    "vpdSettingModeAi", "waterLevelLowSwitch", "waterTempHighSwitch", "waterTempHighValue",
    "waterTempHighValueF", "waterTempLowSwitch", "waterTempLowValue", "waterTempLowValueF",
    "waterTempSettingMode", "waterTempTargetSwitch", "waterTempTargetValue", "waterTempTargetValueF",
)

# Fields the app sends that none of the observed read responses returned.
# 255 and 15 are the
# "nothing bound" sentinels for the external sensor ports; sending 0 instead
# names port and sensor type 0, which the controller rejects.
ADD_DEV_MODE_DEFAULTS: dict[str, int | str] = {
    "insidePort": 255,
    "insidePortAi": 255,
    "outsidePort": 255,
    "outsidePortAi": 255,
    "insideType": 15,
    "insideTypeAi": 15,
    "outsideType": 15,
    "outsideTypeAi": 15,
    "settingModeAi": 1,
    "vpdSettingModeAi": 1,
    "targetTempFAi": 32,
    # The app sends this empty even though the controller has a MAC address.
    "devMacAddr": "",
}


def build_sign(
    access_token: str | None,
    app_version: str,
    secret_id: str | None,
    request_app: str | None,
    request_id: str,
) -> str:
    """Sign a request the way the AC Infinity app does.

    The signature covers the access token, app version, the server-issued
    secretId and requestApp, and the request timestamp. It does not cover the
    request body.
    """

    def md5(value: str) -> str:
        return hashlib.md5(value.encode("utf-8"), usedforsecurity=False).hexdigest()

    left = md5(access_token + app_version) if access_token else md5(app_version)
    right = (
        md5(secret_id + request_app + request_id)
        if secret_id and request_app
        else md5(request_id)
    )

    return md5(left + right)


class ACInfinityClient:
    """Encapsulates http calls to the AC Infinity API"""

    def __init__(self, host: str, email: str, password: str) -> None:
        """
        Args:
            host: The base host of the AC Infinity API
            email: The e-mail to log in as, as configured by the user via config_flow
            password: The password to log in with, as configured by the user via config_flow
        """
        self._host = host
        self._email = email
        self._password = password
        self._user_id: str | None = None
        self._access_token: str | None = None
        self._secret_id: str | None = None
        self._request_app: str | None = None
        self._session: aiohttp.ClientSession | None = None

    async def login(self):
        """Call the log in endpoint with the configured email and password, and obtain the user id to use for subsequent calls"""
        headers = self.__create_headers(use_auth_token=False)

        # AC Infinity API does not accept passwords greater than 25 characters.
        # The Android/iOS app truncates passwords to accommodate for this.  We must do the same.
        normalized_password: str = self._password[0:25]

        response = await self.__post(
            API_URL_LOGIN,
            {"appEmail": self._email, "appPasswordl": normalized_password},
            headers,
        )
        data = response["data"]
        self._user_id = data["appId"]

        # The signature inputs are issued by the server at login. Writes are
        # rejected with a 403 without them.
        self._access_token = data.get("token") or data["appId"]
        self._secret_id = data.get("secretId")
        self._request_app = data.get("requestApp")

        if not self._secret_id or not self._request_app:
            _LOGGER.warning(
                "Login response is missing signing material (secretId present: %s, "
                "requestApp present: %s). Writes to controller settings will fail.",
                bool(self._secret_id),
                bool(self._request_app),
            )

    def is_logged_in(self):
        """returns true if the user id is set, false otherwise"""
        return True if self._user_id else False

    def __ensure_logged_in(self) -> None:
        """Raise when a request requires an authenticated client."""
        if not self.is_logged_in():
            raise ACInfinityClientCannotConnect("AC Infinity client is not logged in.")

    async def get_account_controllers(self):
        """Obtains a list of controllers, including metadata and some sensor values.
        Does not include information related to settings.
        """
        self.__ensure_logged_in()

        headers = self.__create_headers(use_auth_token=True)
        body = await self.__post(
            API_URL_GET_DEVICE_INFO_LIST_ALL, {"userId": self._user_id}, headers
        )
        return body["data"]

    async def get_device_mode_settings(self, controller_id: str | int, device_port: int):
        """Obtains the settings for a particular port on a controller, which includes information
        like speed, sensor triggers, mode timers, etc...

        Args:
            controller_id: The parent controller id of the port
            device_port: The port on the controller of the settings list to grab
        """
        self.__ensure_logged_in()

        headers = self.__create_headers(use_auth_token=True)
        body = await self.__post(
            API_URL_GET_DEV_MODE_SETTING, {"devId": controller_id, "port": device_port}, headers
        )
        return body["data"]

    @staticmethod
    def __transfer_values(device_control_keys: list[str], new_values: dict, existing_values: dict, defaults: dict | None = None):
        updated: dict[str, str | int | bool] = {}
        defaults = defaults or {}
        for key in device_control_keys:
            value = new_values.get(key, existing_values.get(key))
            if value is None:
                # A key the controller reports as null carries no more meaning
                # than one it omits, so both take the documented default.
                value = defaults.get(key, 0)

            if value is None:
                updated[key] = 0
            elif isinstance(value, (dict, list)):
                updated[key] = json.dumps(value)
            elif isinstance(value, bool):
                updated[key] = str(value).lower()
            else:
                updated[key] = value

        return updated

    async def update_device_controls(
        self,
        controller_id: str | int,
        device_port: int,
        key_values: dict[str, int],
        controller_type: int | None = None,
    ):
        """Sets the provided settings on a port to a new values

        Args:
            controller_id: The parent controller id
            device_port: The port on the controller the device is plugged into
            key_values: The key value pairs of settings to set
        """
        self.__ensure_logged_in()

        headers = self.__create_headers(use_auth_token=True)
        body = await self.__post(
            API_URL_GET_DEV_MODE_SETTING, {"devId": controller_id, "port": device_port}, headers
        )
        existing_values = body["data"]

        # Port settings live alongside the nested devSetting object; flatten it
        # so both are available as a single source of values.
        # A null at the top level says nothing about the field, so it must not
        # displace a value the nested object does carry.
        flattened = dict(existing_values.get(DeviceControlKey.DEV_SETTING) or {})
        flattened.update({k: v for k, v in existing_values.items() if v is not None})

        updated = self.__transfer_values(
            list(ADD_DEV_MODE_KEYS), key_values, flattened, ADD_DEV_MODE_DEFAULTS
        )

        # Settings record N belongs to the port the device list calls N.
        # Record 0 is the controller's ALL record, not port 1.
        updated[DeviceControlKey.EXTERNAL_PORT] = int(device_port)

        # The controller applies a mode change only when the settings arrive as
        # a signed request whose urlencoded body carries exactly the fields the
        # app sends. Enumerating every known control key instead submits status
        # fields and the nested devSetting object, which the server accepts with
        # a 200 response and the controller discards.
        form_body = {key: str(value) for key, value in updated.items()}
        _ = await self.__post_signed(API_URL_ADD_DEV_MODE, form_body, controller_type)

    async def update_device_settings(
        self, controller_id: str | int, device_port: int, device_name: str, key_values: dict[str, int]
    ):
        """Sets the provided settings on a port to a new values

        Args:
            controller_id: The parent controller id
            device_port: The port on the controller the device is plugged into
            device_name: The name of the device
            key_values: The key value pairs of settings to set
        """
        self.__ensure_logged_in()

        headers = self.__create_headers(use_auth_token=True)
        body = await self.__post(
            API_URL_GET_DEV_SETTING, {"devId": controller_id, "port": device_port}, headers
        )
        existing_values = body["data"]

        device_settings_keys: list[str] = [
            getattr(AdvancedSettingsKey, attr)
            for attr in dir(AdvancedSettingsKey)
            if not attr.startswith('_')
        ]

        updated = self.__transfer_values(device_settings_keys, key_values, existing_values)
        updated[AdvancedSettingsKey.DEV_NAME] = device_name

        _ = await self.__post(f"{API_URL_UPDATE_ADV_SETTING}?{urlencode(updated)}", None, headers)

    async def update_ai_device_control_and_settings(
        self, controller_id: str | int, device_port: int, key_values: dict[str, int]
    ):
        """Sets the provided settings on a port to a new values

        Args:
            controller_id: id of the controller
            device_port: port of the device
            key_values: The key value pairs of settings to set
        """
        self.__ensure_logged_in()

        headers = self.__create_headers(use_auth_token=True, use_min_version=True)
        body = await self.__post(
            API_URL_GET_DEV_MODE_SETTING, {"devId": controller_id, "port": device_port}, headers
        )
        existing_values = body["data"]

        flattened = existing_values[DeviceControlKey.DEV_SETTING].copy()
        flattened.update(existing_values)

        device_control_keys: list[str] = [
            getattr(ModeAndSettingKeys, attr)
            for attr in dir(ModeAndSettingKeys)
            if not attr.startswith('_')
        ]

        updated = self.__transfer_values(device_control_keys, key_values, flattened)

        at_type = updated[DeviceControlKey.AT_TYPE]
        match at_type:
            case AtType.OFF:
                updated[ModeAndSettingKeys.MODE_AND_SETTING_ID_STR] = "[16,17]"
            case AtType.ON:
                updated[ModeAndSettingKeys.MODE_AND_SETTING_ID_STR] = "[16,18]"
            case AtType.AUTO:
                updated[ModeAndSettingKeys.MODE_AND_SETTING_ID_STR] = "[112,16,19,32,98,99]"
            case AtType.TIMER_TO_ON | AtType.TIMER_TO_OFF:
                updated[ModeAndSettingKeys.MODE_AND_SETTING_ID_STR] = "[16,20,21]"
            case AtType.CYCLE | AtType.SCHEDULE:
                updated[ModeAndSettingKeys.MODE_AND_SETTING_ID_STR] = "[16,22,23,40]"
            case AtType.VPD:
                updated[ModeAndSettingKeys.MODE_AND_SETTING_ID_STR] = "[16,81,32,98,99]"
            case _:
                raise ValueError(f"Unable to find setting id string - Unknown atType {at_type}")

        url = f"{API_URL_MODE_AND_SETTINGS}?{urlencode(updated)}"
        _ = await self.__put(url, headers)

    async def close(self) -> None:
        """Close the session when done"""
        if self._session and not self._session.closed:
            await self._session.close()
        self._session = None

    async def __get_session(self) -> aiohttp.ClientSession:
        """Get or create the HTTP session"""
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(raise_for_status=False)
        return self._session

    async def __post(self, path, post_data, headers):
        """generically make a post request to the AC Infinity API"""
        session = await self.__get_session()
        async with async_timeout.timeout(10), session.post(
            f"{self._host}{path}", data=post_data, headers=headers
        ) as response:
            if response.status != 200:
                raise ACInfinityClientCannotConnect

            body = await response.json()
            if body["code"] != 200:
                if path == API_URL_LOGIN:
                    raise ACInfinityClientInvalidAuth
                else:
                    raise ACInfinityClientRequestFailed(body)

            return body

    async def __put(self, path, headers):
        """generically make a put request to the AC Infinity API"""
        session = await self.__get_session()
        async with async_timeout.timeout(10), session.put(
            f"{self._host}{path}", headers=headers
        ) as response:
            if response.status != 200:
                raise ACInfinityClientCannotConnect

            body = await response.json()
            if body["code"] != 200:
                raise ACInfinityClientRequestFailed(body)

            return body

    def __create_headers(self, use_auth_token: bool, use_min_version: bool = False) -> dict:
        """Creates a header object to use in a request to the AC Infinity API"""
        # noinspection SpellCheckingInspection
        headers: dict = {
            "User-Agent": "okhttp/4.12.0",
        }

        if use_auth_token:
            headers["token"] = self._user_id

        if use_min_version:
            headers["minversion"] = "3.5"

        return headers

    @staticmethod
    def __is_expired_session(error: "ACInfinityClientRequestFailed") -> bool:
        """True when the API rejected a signed request as an expired session."""
        body = error.args[0] if error.args else None
        return isinstance(body, dict) and body.get("code") == 403

    async def __post_signed(self, path: str, form_body: dict, dev_type: int | None):
        """POST a signed request, logging in again if the session was rejected.

        The access token the signature is built from expires, and the app
        obtains fresh credentials on a 403 rather than replaying dead ones.

        Recovery failures are terminal for the service operation. Invalid
        credentials remain distinct from connectivity and request failures.
        """
        try:
            return await self.__post(path, form_body, self.__create_signed_headers(dev_type))
        except ACInfinityClientRequestFailed as err:
            if not self.__is_expired_session(err):
                raise

            _LOGGER.info("Signed request rejected; obtaining fresh credentials")

        try:
            await self.login()
            return await self.__post(path, form_body, self.__create_signed_headers(dev_type))
        except ACInfinityClientRequestFailed as err:
            if self.__is_expired_session(err):
                raise ACInfinityClientInvalidAuth from err
            raise ACInfinityClientRecoveryFailed("Settings recovery request failed") from err
        except (ACInfinityClientCannotConnect, aiohttp.ClientError, TimeoutError) as err:
            raise ACInfinityClientRecoveryFailed("Unable to complete settings recovery") from err

    def __create_signed_headers(self, dev_type: int | None = None) -> dict:
        """Creates headers carrying a request signature.

        The controller applies a settings write only when the request is
        signed; an unsigned write is answered with a 403 "Login Expired".
        """
        request_id = str(int(time.time() * 1000))
        access_token = self._access_token or self._user_id

        headers = {
            "User-Agent": "okhttp/4.12.0",
            "token": access_token or "",
            "requestApp": self._request_app or "",
            "version": APP_VERSION,
            "requestId": request_id,
            "sign": build_sign(
                access_token,
                APP_VERSION,
                self._secret_id,
                self._request_app,
                request_id,
            ),
            "minversion": "",
            "devType": str(dev_type) if dev_type is not None else "",
        }

        return headers


class ACInfinityClientCannotConnect(HomeAssistantError):
    """Error to indicate we cannot connect."""


class ACInfinityClientInvalidAuth(HomeAssistantError):
    """Error to indicate there is invalid auth."""


class ACInfinityClientRecoveryFailed(HomeAssistantError):
    """A failed recovery that must not reenter ordinary request retries."""


class ACInfinityClientRequestFailed(HomeAssistantError):
    """Error to indicate a request failed"""
