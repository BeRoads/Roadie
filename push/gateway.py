import json
import os

try:
    import firebase_admin
    from firebase_admin import credentials as firebase_credentials
    from firebase_admin import messaging as firebase_messaging
except ImportError:  # pragma: no cover - optional dependency
    firebase_admin = None
    firebase_credentials = None
    firebase_messaging = None

try:
    from apns2.client import APNsClient
    from apns2.credentials import TokenCredentials
    from apns2.payload import Payload
except ImportError:  # pragma: no cover - optional dependency
    APNsClient = None
    TokenCredentials = None
    Payload = None


class PushGateway(object):
    """Wrapper around modern push providers (FCM + APNS)."""

    def __init__(self, config, logger, base_dir):
        self.config = config
        self.logger = logger
        self.base_dir = base_dir

        self._fcm_app = None
        self._apns_client = None
        self._apns_topic = self._config_value("push", "apns_bundle_id")
        self.apns_environment = (
            "sandbox"
            if self._config_bool("push", "apns_sandbox_mode", False)
            else "production"
        )

        self._init_fcm()
        self._init_apns()

    def _config_value(self, section, option, default=""):
        try:
            return self.config[section].get(option, default).strip()
        except Exception:
            return default

    def _config_bool(self, section, option, default=False):
        try:
            return self.config[section].getboolean(option)
        except Exception:
            return default

    def _resolve_path(self, maybe_relative_path):
        if not maybe_relative_path:
            return ""
        if os.path.isabs(maybe_relative_path):
            return maybe_relative_path
        return os.path.join(self.base_dir, maybe_relative_path)

    def _init_fcm(self):
        fcm_credentials = self._resolve_path(
            self._config_value("push", "fcm_service_account_file")
        )
        project_id = self._config_value("push", "fcm_project_id")

        if not fcm_credentials:
            self.logger.warning("FCM disabled: missing push.fcm_service_account_file")
            return

        if firebase_admin is None:
            self.logger.warning("FCM disabled: firebase-admin dependency is missing")
            return

        if not os.path.exists(fcm_credentials):
            self.logger.warning(
                "FCM disabled: service account file not found (%s)", fcm_credentials
            )
            return

        options = {}
        if project_id:
            options["projectId"] = project_id

        app_name = "beroads-fcm"
        try:
            self._fcm_app = firebase_admin.get_app(app_name)
        except ValueError:
            cred = firebase_credentials.Certificate(fcm_credentials)
            self._fcm_app = firebase_admin.initialize_app(cred, options, name=app_name)

        self.logger.info("FCM initialized with firebase-admin")

    def _init_apns(self):
        if APNsClient is None or Payload is None:
            self.logger.warning("APNS disabled: apns2 dependency is missing")
            return

        apns_sandbox = self._config_bool("push", "apns_sandbox_mode", False)
        auth_key_file = self._resolve_path(self._config_value("push", "apns_auth_key_file"))
        key_id = self._config_value("push", "apns_key_id")
        team_id = self._config_value("push", "apns_team_id")

        # Preferred mode: token-based APNS auth.
        if auth_key_file and key_id and team_id and TokenCredentials is not None:
            if not os.path.exists(auth_key_file):
                self.logger.warning(
                    "APNS token auth disabled: key file not found (%s)", auth_key_file
                )
            else:
                credentials = TokenCredentials(
                    auth_key_path=auth_key_file, auth_key_id=key_id, team_id=team_id
                )
                self._apns_client = APNsClient(
                    credentials=credentials, use_sandbox=apns_sandbox
                )
                self.logger.info("APNS initialized in token-auth mode")
                return

        # Compatibility mode: certificate auth.
        cert_file = self._resolve_path(self._config_value("push", "apns_certificate"))
        key_file = self._resolve_path(self._config_value("push", "apns_key"))
        if cert_file and os.path.exists(cert_file):
            cert_credentials = cert_file
            if key_file and os.path.exists(key_file):
                cert_credentials = (cert_file, key_file)
            self._apns_client = APNsClient(
                credentials=cert_credentials, use_sandbox=apns_sandbox
            )
            self.logger.warning(
                "APNS initialized in certificate mode (legacy). Configure token auth."
            )
            return

        self.logger.warning("APNS disabled: no valid token or certificate configuration")

    def send_fcm_notification(self, registration_token, data):
        """
        Returns (sent, details, should_drop_token).
        """
        if not self._fcm_app:
            return False, "FCM not configured", False
        if not registration_token:
            return False, "Missing FCM token", False

        payload = {}
        for key, value in data.items():
            if value is None:
                continue
            if isinstance(value, (dict, list)):
                payload[key] = json.dumps(value, separators=(",", ":"))
            else:
                payload[key] = str(value)

        message = firebase_messaging.Message(token=registration_token, data=payload)

        try:
            message_id = firebase_messaging.send(message, app=self._fcm_app)
            return True, message_id, False
        except Exception as exc:  # pragma: no cover - network/provider errors
            error_name = exc.__class__.__name__
            error_message = str(exc)
            normalized = error_message.lower()
            should_drop = (
                error_name in ("UnregisteredError", "SenderIdMismatchError")
                or "not registered" in normalized
                or "invalid registration token" in normalized
            )
            return False, "{}: {}".format(error_name, error_message), should_drop

    def send_apns_notification(self, device_token, alert, custom=None):
        """
        Returns (sent, details, should_drop_token).
        """
        if not self._apns_client:
            return False, "APNS not configured", False
        if not self._apns_topic:
            return False, "Missing push.apns_bundle_id", False
        if not device_token:
            return False, "Missing APNS device token", False

        payload = Payload(alert=alert, sound="default", badge=1, custom=custom or {})

        try:
            result = self._apns_client.send_notification(
                device_token, payload, topic=self._apns_topic
            )
            return True, str(result), False
        except Exception as exc:  # pragma: no cover - network/provider errors
            error_name = exc.__class__.__name__
            error_message = str(exc)
            normalized = error_message.lower()
            should_drop = (
                error_name in ("Unregistered", "BadDeviceToken")
                or "unregistered" in normalized
                or "baddevicetoken" in normalized
                or "device token not for topic" in normalized
            )
            return False, "{}: {}".format(error_name, error_message), should_drop

