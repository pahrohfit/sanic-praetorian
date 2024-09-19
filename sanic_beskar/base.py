import datetime
import re
import textwrap
import uuid
import warnings
from collections.abc import Callable
from importlib import import_module
from importlib.util import find_spec
from typing import TYPE_CHECKING, Any, Optional, Union

import aiofiles
import jinja2
import jwt
import pendulum
import ujson
from passlib.context import CryptContext
from passlib.totp import TOTP
from sanic import Request, Sanic
from sanic.compat import Header
from sanic.log import logger

from sanic_beskar.constants import (
    DEFAULT_CONFIRMATION_SUBJECT,
    DEFAULT_CONFIRMATION_TEMPLATE,
    DEFAULT_HASH_ALLOWED_SCHEMES,
    DEFAULT_HASH_AUTOTEST,
    DEFAULT_HASH_AUTOUPDATE,
    DEFAULT_HASH_DEPRECATED_SCHEMES,
    DEFAULT_HASH_SCHEME,
    DEFAULT_JWT_ALGORITHM,
    DEFAULT_JWT_ALLOWED_ALGORITHMS,
    DEFAULT_PASETO_VERSION,
    DEFAULT_PASSWORD_POLICY,
    DEFAULT_RESET_SUBJECT,
    DEFAULT_RESET_TEMPLATE,
    DEFAULT_ROLES_DISABLED,
    DEFAULT_TOKEN_ACCESS_LIFESPAN,
    DEFAULT_TOKEN_COOKIE_NAME,
    DEFAULT_TOKEN_HEADER_NAME,
    DEFAULT_TOKEN_HEADER_TYPE,
    DEFAULT_TOKEN_PLACES,
    DEFAULT_TOKEN_PROVIDER,
    DEFAULT_TOKEN_REFRESH_LIFESPAN,
    DEFAULT_TOKEN_RESET_LIFESPAN,
    DEFAULT_TOTP_ENFORCE,
    DEFAULT_TOTP_SECRETS_DATA,
    DEFAULT_TOTP_SECRETS_TYPE,
    DEFAULT_USER_CLASS_VALIDATION_METHOD,
    IS_REGISTRATION_TOKEN_CLAIM,
    IS_RESET_TOKEN_CLAIM,
    REFRESH_EXPIRATION_CLAIM,
    RESERVED_CLAIMS,
    VITAM_AETERNUM,
    AccessType,
)
from sanic_beskar.exceptions import (
    AuthenticationError,
    BeskarError,
    BlacklistedError,
    ClaimCollisionError,
    ConfigurationError,
    EarlyRefreshError,
    ExpiredAccessError,
    ExpiredRefreshError,
    InvalidRegistrationToken,
    InvalidResetToken,
    InvalidTokenHeader,
    InvalidUserError,
    LegacyScheme,
    MissingClaimError,
    MissingToken,
    MissingUserError,
    MisusedRegistrationToken,
    MisusedResetToken,
    TOTPRequired,
)
from sanic_beskar.utilities import (
    JSONEncoder,
    duration_from_string,
    get_request,
    is_valid_json,
    normalize_rbac,
)

if TYPE_CHECKING:
    from pyseto import KeyInterface, Paseto, Token


class Beskar:
    """
    Comprises the implementation for the :py:mod:`sanic-beskar`
    :py:mod:`sanic` extension.  Provides a tool that allows password
    authentication and token provision for applications and designated
    endpoints
    """

    def __init__(
        self: "Beskar",
        app: Optional[Sanic] = None,
        user_class: Optional[object] = None,
        is_blacklisted: Optional[Callable] = None,
        encode_token_hook: Optional[Callable] = None,
        refresh_token_hook: Optional[Callable] = None,
        rbac_populate_hook: Optional[Callable] = None,
    ) -> None:
        self.app: Sanic
        self.pwd_ctx: CryptContext = CryptContext()
        self.totp_ctx: TOTP = TOTP(new=True)
        self.totp_secrets_type: str
        self.hash_scheme = None
        self.salt = None
        self.token_provider = "jwt"  # nosec
        self.paseto_ctx: "Paseto"
        self.paseto_key: Union[bytes, str]
        self.paseto_token: "Token"
        self.rbac_definitions: dict = {}

        if app is not None and user_class is not None:
            self.init_app(
                app,
                user_class,
                is_blacklisted,
                encode_token_hook,
                refresh_token_hook,
                rbac_populate_hook,
            )

    async def open_session(self, request: Request) -> None:
        """required for Sanic"""
        pass

    def init_app(
        self,
        app: Sanic,
        user_class: object,
        is_blacklisted: Optional[Callable] = None,
        encode_token_hook: Optional[Callable] = None,
        refresh_token_hook: Optional[Callable] = None,
        rbac_populate_hook: Optional[Callable] = None,
    ) -> Sanic:
        """
        Initializes the :py:class:`Beskar` extension

        Args:
            app (Sanic): The :py:mod:`Sanic` app to bind this extension. Defaults to None.
            user_class (object): Class used to interact with a `User`. Defaults to None.
            is_blacklisted (Callable, optional): A method that may optionally be
                used to check the token against a blacklist when access or refresh
                is requested should take the jti for the token to check as a single
                argument. Returns True if the jti is blacklisted, False otherwise.
                Defaults to `False`.
            encode_token_hook (Callable, optional): A method that may optionally be
                called right before an encoded jwt is generated. Should take
                payload_parts which contains the ingredients for the jwt.
                Defaults to `None`.
            refresh_token_hook (Callable, optional): A method that may optionally be called
                right before an encoded jwt is refreshed. Should take payload_parts
                which contains the ingredients for the jwt. Defaults to `None`.
            rbac_populate_hook (Callable, optional): A method that may optionally be called
                at Beskar init time, or periodcally, to populate a RBAC dictionary mapping
                user Roles to RBAC rights. Defaults to `None`.

        Returns:
            Object: Initialized sanic-beskar object.

        Raises:
            ConfigurationError: Invalid/missing configuration value is detected.
        """

        self.app = app
        app.register_middleware(self.open_session, "request")

        self.roles_disabled = app.config.get(
            "BESKAR_ROLES_DISABLED",
            DEFAULT_ROLES_DISABLED,
        )

        self.hash_autoupdate = app.config.get(
            "BESKAR_HASH_AUTOUPDATE",
            DEFAULT_HASH_AUTOUPDATE,
        )

        self.hash_autotest = app.config.get(
            "BESKAR_HASH_AUTOTEST",
            DEFAULT_HASH_AUTOTEST,
        )

        self.pwd_ctx = CryptContext(
            schemes=app.config.get(
                "BESKAR_HASH_ALLOWED_SCHEMES",
                DEFAULT_HASH_ALLOWED_SCHEMES,
            ),
            default=app.config.get(
                "BESKAR_HASH_SCHEME",
                DEFAULT_HASH_SCHEME,
            ),
            deprecated=app.config.get(
                "BESKAR_HASH_DEPRECATED_SCHEMES",
                DEFAULT_HASH_DEPRECATED_SCHEMES,
            ),
        )

        if self.pwd_ctx.default_scheme().startswith("pbkdf2_"):
            if not find_spec("fastpbkdf2"):
                warnings.warn(
                    textwrap.dedent(
                        """
                        You are using a `pbkdf2` hashing scheme, but didn't install
                          the `fastpbkdf2` module, which will give you like 40%
                          speed improvements. you should go do that now.
                        """
                    ),
                    UserWarning,
                )

        self.user_class = self._validate_user_class(user_class)
        self.is_blacklisted = is_blacklisted or (lambda t: False)
        self.encode_token_hook = encode_token_hook
        self.refresh_token_hook = refresh_token_hook
        self.rbac_populate_hook = rbac_populate_hook
        self.access_lifespan: pendulum.Duration
        self.refresh_lifespan: pendulum.Duration

        # Populate our config defaults
        self.set_config()

        # Run config security checks
        self.audit()

        # If the user provided a base RBAC policy, lets consume it
        if app.config.get("BESKAR_RBAC_POLICY"):
            try:
                self.rbac_definitions = normalize_rbac(app.config.get("BESKAR_RBAC_POLICY", {}))
            except Exception as e:
                raise ConfigurationError(
                    f"Failure loading supplied BESKAR_RBAC_POLICY " f"from config: {e}"
                ) from e

        if isinstance(self.access_lifespan, dict):
            self.access_lifespan = pendulum.duration(**self.access_lifespan)
        elif isinstance(self.access_lifespan, str):
            self.access_lifespan = duration_from_string(self.access_lifespan)
        ConfigurationError.require_condition(
            isinstance(self.access_lifespan, datetime.timedelta),
            "access lifespan was not configured",
        )

        if isinstance(self.refresh_lifespan, dict):
            self.refresh_lifespan = pendulum.duration(**self.refresh_lifespan)
        if isinstance(self.refresh_lifespan, str):
            self.refresh_lifespan = duration_from_string(self.refresh_lifespan)
        ConfigurationError.require_condition(
            isinstance(self.refresh_lifespan, datetime.timedelta),
            "refresh lifespan was not configured",
        )

        if self.token_provider == "paseto":  # nosec B105
            try:  # pragma: no cover
                from pyseto import Key, Paseto, Token  # noqa
            except (ImportError, ModuleNotFoundError) as e:
                raise ConfigurationError(
                    "Trying to use PASETO, " "but you did't install the `pyseto` module"
                ) from e

            self.paseto_parsed_keys: "KeyInterface" = Key.new(
                version=self.paseto_version, purpose="local", key=self.paseto_key
            )
            self.paseto_ctx = Paseto(exp=self.access_lifespan.seconds, include_iat=False)
            self.paseto_token = Token  # type: ignore

        # TODO: add 'issuser', at the very least
        if self.totp_secrets_type:
            """
            If we are saying we are using a TOTP secret protection type,
            we need to ensure the type is something supported (file, string, wallet),
            and that the BESKAR_TOTP_SECRETS_DATA is populated.
            """
            self.totp_secrets_type = self.totp_secrets_type.lower()

            ConfigurationError.require_condition(
                self.totp_secrets_data,
                'If "BESKAR_TOTP_SECRETS_TYPE" is set, you must also'
                'provide a valid value for "BESKAR_TOTP_SECRETS_DATA"',
            )
            if self.totp_secrets_type == "file":
                self.totp_ctx = TOTP.using(secrets_path=app.config.get("BESKAR_TOTP_SECRETS_DATA"))  # type: ignore
            elif self.totp_secrets_type == "string":
                self.totp_ctx = TOTP.using(secrets=app.config.get("BESKAR_TOTP_SECRETS_DATA"))  # type: ignore
            elif self.totp_secrets_type == "wallet":
                self.totp_ctx = TOTP.using(wallet=app.config.get("BESKAR_TOTP_SECRETS_DATA"))  # type: ignore
            else:
                raise ConfigurationError(
                    f'If {"BESKAR_TOTP_SECRETS_TYPE"} is set, it must be one'
                    f'of the following schemes: {["file", "string", "wallet"]}'
                )
        else:
            self.totp_ctx = TOTP.using()  # type: ignore

        self.is_testing = app.config.get("TESTING", False)

        """
        If we are supporting RBAC, lets go pull the current, massage it, and store
        it.  Additionally, setup a listener to know when to go pull updated RBAC
        info whenever the application causes or detects a change.

        Application owner must manually trigger this if there is a change, by sending
        a tickle to the ``beskar.rbac.update`` signal watcher.
        """
        if self.rbac_populate_hook:
            ConfigurationError.require_condition(
                callable(self.rbac_populate_hook),
                "rbac_populate_hook was configured, but doesn't appear callable",
            )

            @app.signal("beskar.rbac.update")
            async def rbac_populate() -> None:
                """Sanic worker to popluate the RBAC policy"""
                _rbac_dump = await self.rbac_populate_hook()  # type: ignore
                self.rbac_definitions = normalize_rbac(_rbac_dump)
                logger.debug(f"RBAC definitions updated: {self.rbac_definitions}")

            @app.before_server_start
            async def init_rbac_populate(app: Sanic) -> None:
                """Sanic worker to call the RBAC policy updater at app init"""
                logger.info("Populating initial RBAC definitions")
                await app.dispatch("beskar.rbac.update")

            app.add_task(init_rbac_populate(app))  # type: ignore

        if not hasattr(app.ctx, "extensions"):
            app.ctx.extensions = {}
        app.ctx.extensions["beskar"] = self

        return app

    def set_config(self) -> None:
        """
        Simple helper to populate all the config settings, making `init_app()` easier to read
        """
        self.encode_key = self.app.config["SECRET_KEY"]
        self.allowed_algorithms = self.app.config.get(
            "JWT_ALLOWED_ALGORITHMS",
            DEFAULT_JWT_ALLOWED_ALGORITHMS,
        )

        self.encode_algorithm = self.app.config.get(
            "JWT_ALGORITHM",
            DEFAULT_JWT_ALGORITHM,
        )

        self.access_lifespan = self.app.config.get(
            "TOKEN_ACCESS_LIFESPAN",
            DEFAULT_TOKEN_ACCESS_LIFESPAN,
        )

        self.refresh_lifespan = self.app.config.get(
            "TOKEN_REFRESH_LIFESPAN",
            DEFAULT_TOKEN_REFRESH_LIFESPAN,
        )

        self.reset_lifespan = self.app.config.get(
            "TOKEN_RESET_LIFESPAN",
            DEFAULT_TOKEN_RESET_LIFESPAN,
        )

        self.token_places = self.app.config.get(
            "TOKEN_PLACES",
            DEFAULT_TOKEN_PLACES,
        )

        self.cookie_name = self.app.config.get(
            "TOKEN_COOKIE_NAME",
            DEFAULT_TOKEN_COOKIE_NAME,
        )

        self.header_name = self.app.config.get(
            "TOKEN_HEADER_NAME",
            DEFAULT_TOKEN_HEADER_NAME,
        )

        self.header_type = self.app.config.get(
            "TOKEN_HEADER_TYPE",
            DEFAULT_TOKEN_HEADER_TYPE,
        )

        self.user_class_validation_method = self.app.config.get(
            "USER_CLASS_VALIDATION_METHOD",
            DEFAULT_USER_CLASS_VALIDATION_METHOD,
        )

        self.confirmation_template = self.app.config.get(
            "BESKAR_CONFIRMATION_TEMPLATE",
            DEFAULT_CONFIRMATION_TEMPLATE,
        )

        self.confirmation_uri = self.app.config.get(
            "BESKAR_CONFIRMATION_URI",
        )

        self.confirmation_sender = self.app.config.get(
            "BESKAR_CONFIRMATION_SENDER",
        )

        self.confirmation_subject = self.app.config.get(
            "BESKAR_CONFIRMATION_SUBJECT",
            DEFAULT_CONFIRMATION_SUBJECT,
        )

        self.reset_template = self.app.config.get(
            "BESKAR_RESET_TEMPLATE",
            DEFAULT_RESET_TEMPLATE,
        )

        self.reset_uri = self.app.config.get(
            "BESKAR_RESET_URI",
        )

        self.reset_sender = self.app.config.get(
            "BESKAR_RESET_SENDER",
        )

        self.reset_subject = self.app.config.get(
            "BESKAR_RESET_SUBJECT",
            DEFAULT_RESET_SUBJECT,
        )

        self.totp_enforce = self.app.config.get(
            "BESKAR_TOTP_ENFORCE",
            DEFAULT_TOTP_ENFORCE,
        )

        self.totp_secrets_type = self.app.config.get(
            "BESKAR_TOTP_SECRETS_TYPE",
            DEFAULT_TOTP_SECRETS_TYPE,
        )

        self.totp_secrets_data = self.app.config.get(
            "BESKAR_TOTP_SECRETS_DATA",
            DEFAULT_TOTP_SECRETS_DATA,
        )

        self.token_provider = self.app.config.get(
            "BESKAR_TOKEN_PROVIDER",
            DEFAULT_TOKEN_PROVIDER,
        )

        self.token_provider = self.token_provider.lower()

        self.paseto_version = self.app.config.get(
            "BESKAR_PASETO_VERSION",
            DEFAULT_PASETO_VERSION,
        )

        self.paseto_key = self.app.config.get(
            "BESKAR_PASETO_KEY",
            self.encode_key,
        )

        self.password_policy = self.app.config.get(
            "BESKAR_PASSWORD_POLICY",
            DEFAULT_PASSWORD_POLICY,
        )

        # Catch anything remaining unset and default
        for setting in DEFAULT_PASSWORD_POLICY:
            if setting not in self.password_policy:
                self.password_policy[setting] = DEFAULT_PASSWORD_POLICY[setting]

    def audit(self) -> None:
        """
        Perform some basic sanity check of settings to make sure the developer didn't
        try to do some blatantly lame stuff
        """
        valid_schemes = self.pwd_ctx.schemes()
        ConfigurationError.require_condition(
            self.hash_scheme in valid_schemes or self.hash_scheme is None,
            f'If {"BESKAR_HASH_SCHEME"} is set, it must be one of the following schemes: {valid_schemes}',
        )

        ConfigurationError.require_condition(
            self.app.config.get("SECRET_KEY") is not None,
            "There must be a SECRET_KEY app config setting set",
        )

        ConfigurationError.require_condition(
            len(self.app.config.SECRET_KEY) >= int(self.password_policy["length"])
            or self.app.config.get("I_MAKE_POOR_CHOICES", False),
            f"your SECRET_KEY is weak in length [{len(self.app.config.SECRET_KEY)} < "
            f"{self.password_policy['length']}]! fix it, or set 'I_MAKE_POOR_CHOICES' to True.",
        )

        ConfigurationError.require_condition(
            self.password_policy["length"] >= 8
            or self.app.config.get("I_MAKE_POOR_CHOICES", False),
            "your password policy secret key length is weak! fix it, or set 'I_MAKE_POOR_CHOICES' to True. "
            "See https://pages.nist.gov/800-63-3/sp800-63b.html#appA for more information.",
        )

        ConfigurationError.require_condition(
            getattr(self, f"encode_{self.token_provider}_token"),
            "Invalid `token_provider` configured. Please check docs and try again.",
        )

        ConfigurationError.require_condition(
            0 < self.paseto_version < 5,
            "Invalid `paseto_version` configured. Valid are [1, 2, 3, 4] only.",
        )

        if self.password_policy["attempt_lockout"] in [0, None, ""]:
            warnings.warn(
                "The PASSWORD_POLICY['attempt_lockout'] value is insecure, "
                "and should not be used. See https://pages.nist.gov/800-63-3/sp800-63b.html#throttle"
            )

    def _validate_user_class(self, user_class: Any) -> Any:
        """
        Validates the supplied :py:data:`user_class` to make sure that it has the
        class methods and attributes necessary to function correctly.
        After validating class methods, will attempt to instantiate a dummy
        instance of the user class to test for the requisite attributes

        Requirements:
        - :py:meth:`lookup` method. Accepts a string parameter, returns instance
        - :py:meth:`identify` method. Accepts an identity parameter, returns instance
        - :py:attribute:`identity` attribute. Provides unique id for the instance
        - :py:attribute:`rolenames` attribute. Provides list of roles attached to instance
        - :py:attribute:`password` attribute. Provides hashed password for instance

        Args:
            user_class (:py:class:`User`): `User` class to use.

        Returns:
            User: Validated `User` object

        Raises:
            :py:exc:`~sanic_beskar.exceptions.BeskarError`: Missing requirements
        """

        BeskarError.require_condition(
            getattr(user_class, "lookup", None) is not None,
            textwrap.dedent(
                """
                The user_class must have a lookup class method:
                user_class.lookup(<str>) -> <user instance>
                """
            ),
        )
        BeskarError.require_condition(
            getattr(user_class, "identify", None) is not None,
            textwrap.dedent(
                """
                The user_class must have an identify class method:
                user_class.identify(<identity>) -> <user instance>
                """
            ),
        )

        dummy_user = None
        try:
            dummy_user = user_class()
        except Exception:
            logger.debug(
                "Skipping instance validation because "
                "user cannot be instantiated without arguments"
            )
        if dummy_user:
            BeskarError.require_condition(
                hasattr(dummy_user, "identity"),
                textwrap.dedent(
                    """
                    Instances of user_class must have an identity attribute:
                    user_instance.identity -> <unique id for instance>
                    """
                ),
            )
            BeskarError.require_condition(
                self.roles_disabled or hasattr(dummy_user, "rolenames"),
                textwrap.dedent(
                    """
                    Instances of user_class must have a rolenames attribute:
                    user_instance.rolenames -> [<role1>, <role2>, ...]
                    """
                ),
            )
            BeskarError.require_condition(
                hasattr(dummy_user, "password"),
                textwrap.dedent(
                    """
                    Instances of user_class must have a password attribute:
                    user_instance.rolenames -> <hashed password>
                    """
                ),
            )

        return user_class

    async def generate_user_totp(self) -> object:
        """
        Generates a :py:mod:`passlib` TOTP for a user. This must be manually saved/updated to the
        :py:class:`User` object.

        . ..note:: The application secret(s) should be stored in a secure location, and each
         secret should contain a large amount of entropy (to prevent brute-force attacks
         if the encrypted keys are leaked).  :py:func:`passlib.generate_secret()` is
         provided as a convenience helper to generate a new application secret of suitable size.
         Best practice is to load these values from a file via secrets_path, pulled in value, or
         utilizing a `passlib wallet`, and then have your application give up permission
         to read this file once it's running.

        :returns: New :py:mod:`passlib` TOTP secret object
        """
        if not self.app.config.get("BESKAR_TOTP_SECRETS_TYPE"):
            warnings.warn(
                textwrap.dedent(
                    """
                    Sanic_Beskar is attempting to generate a new TOTP
                    for a user, but you haven't configured a BESKAR_TOTP_SECRETS_TYPE
                    value, which means you aren't properly encrypting these stored
                    TOTP secrets. *tsk*tsk*
                    """
                ),
                UserWarning,
            )

        return self.totp_ctx.new()

    async def _verify_totp(self, token: str, user: object) -> Any:
        """
        Verifies that a plaintext password matches the hashed version of that
        password using the stored :py:mod:`passlib` password context
        """
        BeskarError.require_condition(
            self.totp_ctx is not None,
            "Beskar must be initialized before this method is available",
        )
        totp_factory = self.totp_ctx.new()

        """
        Optionally, if a :py:class:`User` model has a :py:meth:`get_cache_verify` method,
        call it, and use that response as the :py:data:`last_counter` value.
        """
        _last_counter = None
        if hasattr(user, "get_cache_verify") and callable(user.get_cache_verify):
            _last_counter = await user.get_cache_verify()
        verify = totp_factory.verify(token, user.totp, last_counter=_last_counter)  # type: ignore

        """
        Optionally, if our User model has a :py:func:`cache_verify` function,
        call it, providing the good verification :py:data:`counter` and
        :py:data:`cache_seconds` to be stored by :py:func:`cache_verify` function.

        This is for security against replay attacks, and should ideally be kept
        in a cache, but can be stored in the db
        """
        if hasattr(verify, "counter"):
            if hasattr(user, "cache_verify") and callable(user.cache_verify):
                logger.debug("Updating `User` token verify cache")
                await user.cache_verify(counter=verify.counter, seconds=verify.cache_seconds)

        return verify

    async def authenticate_totp(
        self, user: Union[str, object], token: str, lookup: Optional[str] = "username"
    ) -> Any:
        """
        Verifies that a TOTP validates against the stored TOTP for that
        username.

        If verification passes, the matching user instance is returned.

        If automatically called by :py:func:`authenticate`,
        it accepts a :py:class:`User` object instead of :py:data:`username`
        and skips the :py:func:`lookup` call.

        Args:
            username (Union[str, object]): Username, email, or `User` object to
                perform TOTP authentication against.
            token (str): TOTP token value to validate.
            lookup (str, optional): Type of lookup to perform, either `username` or `email` based.
                Defaults to 'username'.

        Returns:
            :py:class:`User`: Validated `User` object.

        Raises:
            AuthenticationError: Failed TOTP authentication attempt.
        """

        BeskarError.require_condition(
            self.user_class is not None,
            "Beskar must be initialized before this method is available",
        )

        """
        If we are called from `authenticate`, we already looked up the user,
            don't waste the DB call again.
        """
        if isinstance(user, str):
            if lookup == "username":
                user = await self.user_class.lookup(username=user)
            elif lookup == "email":
                user = await self.user_class.lookup(email=user)
            else:
                raise AuthenticationError("Lookup type *must* be either `username` or `email`")
        else:
            user = user

        AuthenticationError.require_condition(
            user is not None
            and hasattr(user, "totp")
            and user.totp
            and await is_valid_json(user.totp),
            "TOTP challenge is not properly configured for this user",
        )
        AuthenticationError.require_condition(
            user is not None
            and token is not None
            and await self._verify_totp(
                token,
                user,
            ),
            "The credentials provided are missing or incorrect",
        )

        return user

    async def authenticate(
        self,
        user: str,
        password: str,
        token: Optional[str] = None,
        lookup: Optional[str] = "username",
    ) -> object:
        """
        Verifies that a password matches the stored password for that username or
        email.
        If verification passes, the matching user instance is returned

        .. note:: If :py:data:`BESKAR_TOTP_ENFORCE` is set to `True`
                  (default), and a user has a TOTP configuration, this call
                  must include the `token` value, or it will raise a
                  :py:exc:`~sanic_beskar.exceptions.TOTPRequired` exception
                  and not return the user.

                  This means either you will need to call it again, providing
                  the `token` value from the user, or separately call
                  :py:func:`authenticate_totp`,
                  which only performs validation of the `token` value,
                  and not the users password.

                  **Choose your own adventure.**

        Args:
            user (str): Username or email to authenticate
            password (str): Password to validate against
            token (str, optional): TOTP Token value to validate against.
                Defaults to None.
            lookup (str, optional): Type of lookup to perform, either `username` or `email` based.
                Defaults to 'username'.

        Returns:
            :py:class:`User`: Authenticated `User` object.

        Raises:
            AuthenticationError: Failed password, TOTP, or password+TOTP attempt.
            TOTPRequired: Account is required to supply TOTP.
        """

        BeskarError.require_condition(
            self.user_class is not None,
            "Beskar must be initialized before this method is available",
        )
        if lookup == "username":
            user_o = await self.user_class.lookup(username=user)
        elif lookup == "email":
            user_o = await self.user_class.lookup(email=user)
        else:
            raise AuthenticationError("Lookup type *must* be either `username` or `email`")

        AuthenticationError.require_condition(
            user_o is not None
            and self._verify_password(
                password,
                user_o.password,
            ),
            "The credentials provided are missing or incorrect",
        )

        """
        If we provided a TOTP token in this `authenticate` call,
            or if the user is required to use TOTP, instead of
            as a separate call to `authenticate_totp`, then lets do it here.
        Failure to provide a TOTP token, when the user is required to use
            TOTP, results in a `TOTPRequired` exception, and the calling
            application will be required to either re-call `authenticate`
            with all 3 arugements, or call `authenticate_otp` directly.
        """
        if hasattr(user_o, "totp") or token:
            if token:
                user_o = await self.authenticate_totp(user_o, token)
            elif self.totp_enforce:
                raise TOTPRequired(
                    "Password authentication successful -- "
                    f"TOTP still *required* for user '{user_o.username}'."
                )

        """
        If we are set to BESKAR_HASH_AUTOUPDATE then check our hash
            and if needed, update the user.  The developer is responsible
            for using the returned user object and updating the data
            storage endpoint.

        Else, if we are set to BESKAR_HASH_AUTOTEST then check out hash
            and return exception if our hash is using the wrong scheme,
            but don't modify the user.
        """
        if self.hash_autoupdate:
            await self.verify_and_update(user=user_o, password=password)
        elif self.hash_autotest:
            await self.verify_and_update(user=user_o)

        return user_o

    def _verify_password(self, raw_password: str, hashed_password: str) -> bool:
        """
        Verifies that a plaintext password matches the hashed version of that
        password using the stored :py:mod:`passlib` password context
        """
        BeskarError.require_condition(
            self.pwd_ctx is not None,
            "Beskar must be initialized before this method is available",
        )
        return self.pwd_ctx.verify(raw_password, hashed_password)

    def _check_user(self, user: object) -> bool:
        """
        Checks to make sure that a user is valid. First, checks that the user
        is not None. If this check fails, a MissingUserError is raised. Next,
        checks if the user has a validation method. If the method does not
        exist, the check passes. If the method exists, it is called. If the
        result of the call is not truthy, a
        :py:exc:`~sanic_beskar.exceptions.InvalidUserError` is raised.
        """
        MissingUserError.require_condition(
            user is not None,
            "Could not find the requested user",
        )
        user_validate_method = getattr(user, self.user_class_validation_method, None)
        if user_validate_method is None:
            return True

        InvalidUserError.require_condition(
            user_validate_method(),
            "The user is not valid or has had access revoked",
        )

        return True

    async def encode_paseto_token(
        self,
        user: Any,
        override_access_lifespan: Optional[pendulum.Duration] = None,
        override_refresh_lifespan: Optional[pendulum.Duration] = None,
        bypass_user_check: Optional[bool] = False,
        is_registration_token: Optional[bool] = False,
        is_reset_token: Optional[bool] = False,
        **custom_claims: Optional[dict],
    ) -> str:
        """
        Encodes user data into a PASETO token that can be used for authorization
        at protected endpoints

        .. note:: Note that any claims supplied as `custom_claims` here must be
          :py:mod:`json` compatible types.

        Args:
            user (:py:class:`User`): `User` to generate a token for.
            override_access_lifespan (pendulum.Duration, optional): Override's the
                instance's access lifespan to set a custom duration after which
                the new token's accessibility will expire. May not exceed the
                :py:data:`refresh_lifespan`. Defaults to `None`.
            override_refresh_lifespan (pendulum.Duration, optional): Override's the
                instance's refresh lifespan to set a custom duration after which
                the new token's refreshability will expire. Defaults to `None`.
            bypass_user_check (bool, optional): Override checking the user for
                being real/active.  Used for registration token generation.
                Defaults to `False`.
            is_registration_token (bool, optional): Indicates that the token will
                be used only for email-based registration. Defaults to `False`.
            is_reset_token (bool, optional): Indicates that the token will
                be used only for lost password reset. Defaults to `False`.
            custom_claims (dict, optional): Additional claims that should be packed
                in the payload. Defaults to `None`.

        Returns:
            str: Encoded PASETO token string.

        Raises:
            ClaimCollisionError: Tried to supply a RESERVED_CLAIM in the `custom_claims`.
        """

        ClaimCollisionError.require_condition(
            set(custom_claims.keys()).isdisjoint(RESERVED_CLAIMS),
            "The custom claims collide with required claims",
        )
        if not bypass_user_check:
            self._check_user(user)

        moment = pendulum.now("UTC")
        if override_refresh_lifespan is None:
            refresh_lifespan = self.refresh_lifespan
        else:
            refresh_lifespan = override_refresh_lifespan
        refresh_expiration = (moment + refresh_lifespan).int_timestamp

        if override_access_lifespan is None:
            access_lifespan = self.access_lifespan
        else:
            access_lifespan = override_access_lifespan
        access_expiration = min(
            (moment + access_lifespan).int_timestamp,
            refresh_expiration,
        )

        payload_parts = {
            "iat": moment.int_timestamp,
            "exp": access_expiration,
            "jti": str(uuid.uuid4()),
            "id": user.identity,
            "rls": ",".join(user.rolenames),
            REFRESH_EXPIRATION_CLAIM: refresh_expiration,
        }
        if is_registration_token:
            payload_parts[IS_REGISTRATION_TOKEN_CLAIM] = True
        if is_reset_token:
            payload_parts[IS_RESET_TOKEN_CLAIM] = True
        logger.debug(
            f"Attaching custom claims: {custom_claims}",
        )
        payload_parts.update(custom_claims)

        if self.encode_token_hook:
            self.encode_token_hook(**payload_parts)

        # PASETO stores its own EXP as seconds from now()
        time_delta = access_expiration - moment.int_timestamp

        return self.paseto_ctx.encode(
            self.paseto_parsed_keys,
            payload_parts,
            serializer=ujson,
            exp=time_delta,
        ).decode(
            "utf-8"
        )  # bytes by default, which are ugly

    async def encode_jwt_token(
        self,
        user: Any,
        override_access_lifespan: Optional[pendulum.Duration] = None,
        override_refresh_lifespan: Optional[pendulum.Duration] = None,
        bypass_user_check: Optional[bool] = False,
        is_registration_token: Optional[bool] = False,
        is_reset_token: Optional[bool] = False,
        **custom_claims: Optional[dict],
    ) -> str:
        """
        Encodes user data into a jwt token that can be used for authorization
        at protected endpoints

        Args:
            user (:py:class:`User`): `User` to generate a token for.
            override_access_lifespan (pendulum.Duration, optional): Override's the
                instance's access lifespan to set a custom duration after which
                the new token's accessibility will expire. May not exceed the
                :py:data:`refresh_lifespan`. Defaults to `None`.
            override_refresh_lifespan (pendulum.Duration, optional): Override's the
                instance's refresh lifespan to set a custom duration after which
                the new token's refreshability will expire. Defaults to `None`.
            bypass_user_check (bool, optional): Override checking the user for
                being real/active.  Used for registration token generation.
                Defaults to `False`.
            is_registration_token (bool, optional): Indicates that the token will
                be used only for email-based registration. Defaults to `False`.
            is_reset_token (bool, optional): Indicates that the token will
                be used only for lost password reset. Defaults to `False`.
            custom_claims (dict, optional): Additional claims that should be packed
                in the payload. Defaults to `None`.

        Returns:
            str: Encoded JWT token string.

        Raises:
            ClaimCollisionError: Tried to supply a RESERVED_CLAIM in the `custom_claims`.
        """

        ClaimCollisionError.require_condition(
            set(custom_claims.keys()).isdisjoint(RESERVED_CLAIMS),
            "The custom claims collide with required claims",
        )
        if not bypass_user_check:
            self._check_user(user)

        moment = pendulum.now("UTC")

        if override_refresh_lifespan is None:
            refresh_lifespan = self.refresh_lifespan
        else:
            refresh_lifespan = override_refresh_lifespan
        refresh_expiration = (moment + refresh_lifespan).int_timestamp

        if override_access_lifespan is None:
            access_lifespan = self.access_lifespan
        else:
            access_lifespan = override_access_lifespan
        access_expiration = min(
            (moment + access_lifespan).int_timestamp,
            refresh_expiration,
        )

        payload_parts = {
            "iat": moment.int_timestamp,
            "exp": access_expiration,
            "jti": str(uuid.uuid4()),
            "id": user.identity,
            "rls": ",".join(user.rolenames),
            REFRESH_EXPIRATION_CLAIM: refresh_expiration,
        }
        if is_registration_token:
            payload_parts[IS_REGISTRATION_TOKEN_CLAIM] = True
        if is_reset_token:
            payload_parts[IS_RESET_TOKEN_CLAIM] = True
        logger.debug(f"Attaching custom claims: {custom_claims}")
        payload_parts.update(custom_claims)

        if self.encode_token_hook:
            self.encode_token_hook(**payload_parts)
        return jwt.encode(
            payload_parts,
            self.encode_key,
            self.encode_algorithm,
            json_encoder=JSONEncoder,
        )

    async def encode_token(
        self,
        user: object,
        override_access_lifespan: Optional[pendulum.Duration] = None,
        override_refresh_lifespan: Optional[pendulum.Duration] = None,
        bypass_user_check: Optional[bool] = False,
        is_registration_token: Optional[bool] = False,
        is_reset_token: Optional[bool] = False,
        **custom_claims: Optional[dict],
    ) -> str:
        """
        Wrapper function to encode user data into a `insert_type_here` token
        that can be used for authorization at protected endpoints.

        Calling this will allow your app configuration to automagically create
        the appropriate token type.

        Args:
            user (:py:class:`User`): `User` to generate a token for.
            override_access_lifespan (pendulum.Duration, optional): Override's the
                instance's access lifespan to set a custom duration after which
                the new token's accessibility will expire. May not exceed the
                :py:data:`refresh_lifespan`. Defaults to `None`.
            override_refresh_lifespan (pendulum.Duration, optional): Override's the
                instance's refresh lifespan to set a custom duration after which
                the new token's refreshability will expire. Defaults to `None`.
            bypass_user_check (bool, optional): Override checking the user for
                being real/active.  Used for registration token generation.
                Defaults to `False`.
            is_registration_token (bool, optional): Indicates that the token will
                be used only for email-based registration. Defaults to `False`.
            is_reset_token (bool, optional): Indicates that the token will
                be used only for lost password reset. Defaults to `False`.
            custom_claims (dict, optional): Additional claims that should be packed
                in the payload. Defaults to `None`.

        Returns:
            str: Encoded token string of application configuration type `TOKEN_PROVIDER`.

        Raises:
            ClaimCollisionError: Tried to supply a RESERVED_CLAIM in the `custom_claims`.
        """

        _token: str = await getattr(self, f"encode_{self.token_provider}_token")(
            user,
            override_access_lifespan=override_access_lifespan,
            override_refresh_lifespan=override_refresh_lifespan,
            bypass_user_check=bypass_user_check,
            is_registration_token=is_registration_token,
            is_reset_token=is_reset_token,
            **custom_claims,
        )

        return _token

    async def encode_eternal_token(self, user: object, **custom_claims: Optional[dict]) -> str:
        """
        This utility function encodes an application configuration defined
        type token that never expires

        .. note:: This should be used sparingly since the token could become
                  a security concern if it is ever lost. If you use this
                  method, you should be sure that your application also
                  implements a blacklist so that a given token can be blocked
                  should it be lost or become a security concern

        Args:
            user (:py:class:`User`): `User` to generate a token for.
            custom_claims (dict, optional): Additional claims that should be packed
                in the payload. Defaults to `None`.

        Returns:
            str: Encoded, *never expiring*, token string of application configuration
            type `TOKEN_PROVIDER`.
        """

        return await self.encode_token(
            user,
            override_access_lifespan=VITAM_AETERNUM,
            override_refresh_lifespan=VITAM_AETERNUM,
            custom_claims=custom_claims,
        )

    async def refresh_token(
        self, token: str, override_access_lifespan: Optional[pendulum.Duration] = None
    ) -> str:
        """
        Wrapper function to creates a new token for a user if and only if the old
        token's access permission is expired but its refresh permission is not yet
        expired. The new token's refresh expiration moment is the same as the old
        token's, but the new token's access expiration is refreshed.

        Token type is determined by application configuration, when using this
        helper function.

        Args:
            token (str): The existing token that needs to be replaced with a new,
                refreshed token.
            override_access_lifespan (_type_, optional): Override's the instance's
                access lifespan to set a custom duration after which the new
                token's accessibility will expire. May not exceed the
                :py:data:`refresh_lifespan`. Defaults to `None`.

        Returns:
            str: Encoded token string of application configuration type `TOKEN_PROVIDER`.
        """

        _token: str = await getattr(self, f"refresh_{self.token_provider}_token")(
            token=token, override_access_lifespan=override_access_lifespan
        )

        return _token

    async def refresh_paseto_token(
        self, token: str, override_access_lifespan: Optional[pendulum.Duration] = None
    ) -> bytes:
        """
        Creates a new PASETO token for a user if and only if the old token's access
        permission is expired but its refresh permission is not yet expired.
        The new token's refresh expiration moment is the same as the old
        token's, but the new token's access expiration is refreshed

        Args:
            token (str): The existing token that needs to be replaced with a new,
                refreshed token.
            override_access_lifespan (_type_, optional): Override's the instance's
                access lifespan to set a custom duration after which the new
                token's accessibility will expire. May not exceed the
                :py:data:`refresh_lifespan`. Defaults to `None`.

        Returns:
            bytes: Encoded PASETO token string.
        """

        moment = pendulum.now("UTC")
        data = await self.extract_token(token, access_type=AccessType.refresh)

        user = await self.user_class.identify(data["id"])
        self._check_user(user)

        if not override_access_lifespan:
            access_lifespan = self.access_lifespan
        else:
            access_lifespan = override_access_lifespan
        refresh_expiration = data[REFRESH_EXPIRATION_CLAIM]
        access_expiration = min(
            (moment + access_lifespan).int_timestamp,
            refresh_expiration,
        )

        custom_claims = {k: v for (k, v) in data.items() if k not in RESERVED_CLAIMS}
        payload_parts = {
            "iat": moment.int_timestamp,
            "exp": access_expiration,
            "jti": data["jti"],
            "id": data["id"],
            "rls": ",".join(user.rolenames),
            REFRESH_EXPIRATION_CLAIM: refresh_expiration,
        }
        payload_parts.update(custom_claims)

        if self.refresh_token_hook:
            self.refresh_token_hook(**payload_parts)

        # PASETO stores its own EXP as seconds from now()
        time_delta = access_expiration - moment.int_timestamp

        _token: bytes = self.paseto_ctx.encode(
            self.paseto_parsed_keys,
            payload_parts,
            serializer=ujson,
            exp=time_delta,
        )

        return _token

    async def refresh_jwt_token(
        self, token: str, override_access_lifespan: Optional[pendulum.Duration] = None
    ) -> str:
        """
        Creates a new JWT token for a user if and only if the old token's access
        permission is expired but its refresh permission is not yet expired.
        The new token's refresh expiration moment is the same as the old
        token's, but the new token's access expiration is refreshed

        Args:
            token (str): The existing token that needs to be replaced with a new,
                refreshed token.
            override_access_lifespan (_type_, optional): Override's the instance's
                access lifespan to set a custom duration after which the new
                token's accessibility will expire. May not exceed the
                :py:data:`refresh_lifespan`. Defaults to `None`.

        Returns:
            str: Encoded JWT token string.
        """

        moment = pendulum.now("UTC")
        data = await self.extract_token(token, access_type=AccessType.refresh)

        user = await self.user_class.identify(data["id"])
        self._check_user(user)

        if not override_access_lifespan:
            access_lifespan: pendulum.Duration = self.access_lifespan
        else:
            access_lifespan = override_access_lifespan
        refresh_expiration = data[REFRESH_EXPIRATION_CLAIM]
        access_expiration = min(
            (moment + access_lifespan).int_timestamp,
            refresh_expiration,
        )

        custom_claims = {k: v for (k, v) in data.items() if k not in RESERVED_CLAIMS}
        payload_parts = {
            "iat": moment.int_timestamp,
            "exp": access_expiration,
            "jti": data["jti"],
            "id": data["id"],
            "rls": ",".join(user.rolenames),
            REFRESH_EXPIRATION_CLAIM: refresh_expiration,
        }
        payload_parts.update(custom_claims)

        if self.refresh_token_hook:
            self.refresh_token_hook(**payload_parts)
        return jwt.encode(
            payload_parts,
            self.encode_key,
            self.encode_algorithm,
        )

    async def extract_token(self, token: str, access_type: AccessType = AccessType.access) -> dict:
        """
        Wrapper function to extract a data dictionary from a token. This
        function will automagically identify the token type based upon
        application configuration and process it accordingly.

        Args:
            token (str): Token to be processed
            access_type (AccessType): Type of token being processed

        Returns:
            dict: Extracted token as a `dict`
        """
        _token: dict = await getattr(self, f"extract_{self.token_provider}_token")(
            token=token, access_type=access_type
        )

        return _token

    async def extract_paseto_token(
        self, token: Union[bytes, str], access_type: AccessType = AccessType.access
    ) -> dict:
        """
        Extracts a data dictionary from a PASETO token.

        Args:
            token (str): Token to be processed
            access_type (AccessType): Type of token being processed

        Returns:
            dict: Extracted token as a `dict`
        """

        # Note: we disable exp verification because we will do it ourselves
        failed = None
        keys = (
            self.paseto_parsed_keys
            if isinstance(self.paseto_parsed_keys, list)
            else [self.paseto_parsed_keys]
        )
        t = self.paseto_token.new(token)
        for k in keys:
            if k.header != t.header:
                continue
            try:
                if k.purpose == "local":
                    t.payload = k.decrypt(t.payload, t.footer)
                else:
                    t.payload = k.verify(t.payload, t.footer)
                try:
                    t.payload = ujson.loads(t.payload)
                except Exception as err:
                    raise InvalidTokenHeader("Failed to deserialize the payload.") from err
            except Exception as err:
                failed = err
        if failed:
            raise failed

        # Convert to expected time format
        t.payload["exp"] = pendulum.parse(t.payload["exp"]).int_timestamp  # type: ignore
        self._validate_token_data(t.payload, access_type=access_type)
        _payload: dict = t.payload
        return _payload

    async def extract_jwt_token(
        self, token: str, access_type: AccessType = AccessType.access
    ) -> dict:
        """
        Extracts a data dictionary from a JWT token.

        Args:
            token (str): Token to be processed
            access_type (AccessType): Type of token being processed

        Returns:
            dict: Extracted token as a `dict`
        """

        # Note: we disable exp verification because we will do it ourselves
        with InvalidTokenHeader.handle_errors("failed to decode JWT token"):
            data: dict = jwt.decode(
                token,
                self.encode_key,
                algorithms=self.allowed_algorithms,
                options={"verify_exp": False},
            )
        self._validate_token_data(data, access_type=access_type)
        return data

    def _validate_token_data(self, data: dict, access_type: AccessType) -> None:
        """
        Validates that the data for a jwt token is valid
        """
        MissingClaimError.require_condition(
            "jti" in data,
            "Token is missing jti claim",
        )
        BlacklistedError.require_condition(
            not self.is_blacklisted(data["jti"]),
            "Token has a blacklisted jti",
        )
        MissingClaimError.require_condition(
            "id" in data,
            "Token is missing id field",
        )
        MissingClaimError.require_condition(
            "exp" in data,
            "Token is missing exp claim",
        )
        MissingClaimError.require_condition(
            REFRESH_EXPIRATION_CLAIM in data,
            f"Token is missing {REFRESH_EXPIRATION_CLAIM} claim",
        )
        moment = pendulum.now("UTC").int_timestamp
        if access_type == AccessType.access:
            MisusedRegistrationToken.require_condition(
                IS_REGISTRATION_TOKEN_CLAIM not in data,
                "registration token used for access",
            )
            MisusedResetToken.require_condition(
                IS_RESET_TOKEN_CLAIM not in data,
                "password reset token used for access",
            )
            ExpiredAccessError.require_condition(
                moment <= data["exp"],
                "access permission has expired",
            )
        elif access_type == AccessType.refresh:
            MisusedRegistrationToken.require_condition(
                IS_REGISTRATION_TOKEN_CLAIM not in data,
                "registration token used for refresh",
            )
            MisusedResetToken.require_condition(
                IS_RESET_TOKEN_CLAIM not in data,
                "password reset token used for refresh",
            )
            EarlyRefreshError.require_condition(
                moment > data["exp"],
                "access permission for token has not expired. may not refresh",
            )
            ExpiredRefreshError.require_condition(
                moment <= data[REFRESH_EXPIRATION_CLAIM],
                "refresh permission for token has expired",
            )
        elif access_type == AccessType.register:
            ExpiredAccessError.require_condition(
                moment <= data["exp"],
                "register permission has expired",
            )
            InvalidRegistrationToken.require_condition(
                IS_REGISTRATION_TOKEN_CLAIM in data,
                "invalid registration token used for verification",
            )
            MisusedResetToken.require_condition(
                IS_RESET_TOKEN_CLAIM not in data,
                "password reset token used for registration",
            )
        elif access_type == AccessType.reset:
            MisusedRegistrationToken.require_condition(
                IS_REGISTRATION_TOKEN_CLAIM not in data,
                "registration token used for reset",
            )
            ExpiredAccessError.require_condition(
                moment <= data["exp"],
                "reset permission has expired",
            )
            InvalidResetToken.require_condition(
                IS_RESET_TOKEN_CLAIM in data,
                "invalid reset token used for verification",
            )

    def _unpack_header(self, headers: Header) -> Union[str, None]:
        """
        Unpacks a token from a request header
        """
        token_header: str = headers.get(self.header_name, "")
        MissingToken.require_condition(
            token_header,
            f"Token not found in headers under '{self.header_name}'",
        )

        match = re.match(self.header_type + r"\s*([\w\.-]+)", token_header)
        InvalidTokenHeader.require_condition(
            match is not None,
            "Token header structure is invalid",
        )
        return match.group(1)  # type: ignore

    def read_token_from_header(self, request: Request) -> Union[str, None]:
        """
        Unpacks a token from the current sanic request

        Args:
            request (Request): Current Sanic `Request`.

        Returns:
            str: Unpacked token from header.
        """

        _request = get_request(request)
        return self._unpack_header(_request.headers)

    def _unpack_cookie(self, cookies: dict = {}) -> str:
        """
        Unpacks a jwt token from a request cookies
        """

        token_cookie: str = cookies.get(self.cookie_name, "")
        MissingToken.require_condition(
            token_cookie, f"Token not found in cookie under '{self.cookie_name}'"
        )
        return token_cookie

    def read_token_from_cookie(self, request: Request) -> str:
        """
        Unpacks a token from the current sanic request

        Args:
            request (Request): Current Sanic `Request`.

        Returns:
            str: Unpacked token from cookie.
        """

        _request = get_request(request)
        return self._unpack_cookie(_request.cookies)

    def read_token(self, request: Request) -> str:
        """
        Tries to unpack the token from the current sanic request
        in the locations configured by :py:data:`TOKEN_PLACES`.
        Check-Order is defined by the value order in :py:data:`TOKEN_PLACES`.

        Args:
            request (sanic.Request): Sanic ``request`` object

        Returns:
            str: Token.

        Raises:
            :py:exc:`~sanic_beskar.exceptions.MissingToken`: Token is not found in any
                :py:data:`~sanic_beskar.constants.TOKEN_PLACES`
        """

        _request = get_request(request)
        for place in self.token_places:
            try:
                _token: str = getattr(self, f"read_token_from_{place.lower()}")(_request)
                return _token
            except MissingToken:
                pass
            except AttributeError:
                warnings.warn(
                    textwrap.dedent(
                        f"""
                        Sanic_Beskar hasn't implemented reading tokens
                        from location '{place.lower()}'.
                        Please reconfigure TOKEN_PLACES.
                        Values accepted in TOKEN_PLACES are:
                        {self.token_places}
                        """
                    ),
                    UserWarning,
                )

        raise MissingToken(
            textwrap.dedent(
                f"""
                Could not find token in any
                 of the given locations: {self.token_places}
                """
            ).replace("\n", "")
        )

    async def pack_header_for_user(
        self,
        user: Union[object, str],
        override_access_lifespan: Optional[pendulum.Duration] = None,
        override_refresh_lifespan: Optional[pendulum.Duration] = None,
        bypass_user_check: Optional[bool] = False,
        is_registration_token: Optional[bool] = False,
        is_reset_token: Optional[bool] = False,
        **custom_claims: Optional[dict],
    ) -> dict:
        """
        Encodes a jwt token and packages it into a header dict for a given user

        Args:
            user (:py:class:`User`): The user to package the header for
            override_access_lifespan (:py:data:`pendulum`):  Override's the instance's
                access lifespan to set a custom duration after which the new token's
                accessibility will expire. May not exceed the :py:data:`refresh_lifespan`
            override_refresh_lifespan (:py:data:`pendulum`): Override's the instance's
                refresh lifespan to set a custom duration after which the new token's
                refreshability will expire.
            custom_claims (dict): Additional claims that should be packed in the payload. Note
                that any claims supplied here must be :py:mod:`json` compatible types

        Returns:
            dict: Updated header, including token
        """

        token = await self.encode_token(
            user,
            override_access_lifespan=override_access_lifespan,
            override_refresh_lifespan=override_refresh_lifespan,
            bypass_user_check=bypass_user_check,
            is_registration_token=is_registration_token,
            is_reset_token=is_reset_token,
            **custom_claims,
        )
        return {self.header_name: f"{self.header_type} {token}"}

    async def send_registration_email(
        self,
        email: str,
        user: object,
        template: Optional[Union[str, jinja2.nodes.Template]] = None,
        confirmation_sender: Optional[str] = None,
        confirmation_uri: Optional[str] = None,
        subject: Optional[str] = None,
        override_access_lifespan: Optional[pendulum.Duration] = None,
    ) -> dict:
        """
        Sends a registration email to a new user, containing a time expiring
        token usable for validation.  This requires your application
        is initialized with a `mail` extension, which supports
        sanic-mailing's :py:class:`Message` object and a
        :py:meth:`send_message` method.

        Args:
            user (:py:class:`User`): The user object to tie claim to
                (username, id, email, etc)
            template (Optional, :py:data:`filehandle`): HTML Template for confirmation
                email. If not provided, a stock entry is used.
            confirmation_sender (Optional, str): The sender that should be attached to the
                confirmation email. Overrides the :py:data:`BESKAR_CONFIRMATION_SENDER`
                config setting.
            confirmation_uri (Optional, str): The uri that should be visited to complete email
                registration. Should usually be a uri to a frontend or external service
                that calls a 'finalize' method in the api to complete registration. Will
                override the :py:data:`BESKAR_CONFIRMATION_URI` config setting.
            subject (Optional, str): The registration email subject.  Will override the
                :py:data:`BESKAR_CONFIRMATION_SUBJECT` config setting.
            override_access_lifespan (Optional, :py:data:`pendulum`): Overrides the
                :py:data:`TOKEN_ACCESS_LIFESPAN` to set an access lifespan for the
                registration token.

        Returns:
            dict: Summary of information sent, along with the `result` from mail send. (Essentially
            the response of :py:func:`send_token_email`).
        """

        if subject is None:
            subject = self.confirmation_subject

        if confirmation_uri is None:
            confirmation_uri = self.confirmation_uri

        sender = confirmation_sender or self.confirmation_sender

        logger.debug(f"Generating token with lifespan: {override_access_lifespan}")
        custom_token = await self.encode_token(
            user,
            override_access_lifespan=override_access_lifespan,
            bypass_user_check=True,
            is_registration_token=True,
        )

        _return: dict = await self.send_token_email(
            email,
            user=user,
            template=template,
            action_sender=sender,
            action_uri=confirmation_uri,
            subject=subject,
            custom_token=custom_token,
        )

        return _return

    async def send_reset_email(
        self,
        email: str,
        template: Optional[Union[str, jinja2.nodes.Template]] = None,
        reset_sender: Optional[str] = None,
        reset_uri: Optional[str] = None,
        subject: Optional[str] = None,
        override_access_lifespan: Optional[pendulum.Duration] = None,
    ) -> dict:
        """
        Sends a password reset email to a user, containing a time expiring
        token usable for validation.  This requires your application
        is initialized with a :py:mod:`mail` extension, which supports
        sanic-mailing's :py:class:`Message` object and a
        :py:meth:`send_message()` method.

        Args:
            email (str): The email address to attempt to send to.
            template (Optional, :py:data:`filehandle`): HTML Template for reset email.
                If not provided, a stock entry is used.
            reset_sender (Optional, str): The sender that should be attached to the
                reset email. Defaults to :py:data:`BESKAR_RESET_SENDER` config setting.
            reset_uri (Optional, str): The uri that should be visited to complete password
                reset. Should usually be a uri to a frontend or external service that calls
                the 'validate_reset_token()' method in the api to complete reset. Defaults to
                :py:data:`BESKAR_RESET_URI` config setting.
            subject (Optional, str): The reset email subject. Defaults to
                :py:data:`BESKAR_RESET_SUBJECT` config setting.
            override_access_lifespan (Optional, :py:data:`pendulum`): Overrides the
                :py:data:`TOKEN_ACCESS_LIFESPAN` to set an access lifespan for the registration token.
                Defaults to :py:data:`TOKEN_ACCESS_LIFESPAN` config setting.

        Returns:
            dict: Summary of information sent, along with the `result` from mail send. (Essentially
            the response of :py:func:`send_token_email`).
        """
        if subject is None:
            subject = self.reset_subject

        if reset_uri is None:
            reset_uri = self.reset_uri

        sender = reset_sender or self.reset_sender

        user = await self.user_class.lookup(email=email)
        MissingUserError.require_condition(
            user is not None,
            "Could not find the requested user",
        )

        logger.debug(f"Generating token with lifespan: {override_access_lifespan}")
        custom_token = await self.encode_token(
            user,
            override_access_lifespan=override_access_lifespan,
            bypass_user_check=False,
            is_reset_token=True,
        )

        _return: dict = await self.send_token_email(
            user.email,
            user=user,
            template=template,
            action_sender=sender,
            action_uri=reset_uri,
            subject=subject,
            custom_token=custom_token,
        )
        return _return

    async def send_token_email(
        self,
        email: str,
        user: object,
        template: Optional[Union[str, jinja2.nodes.Template]] = None,
        action_sender: Optional[str] = "",
        action_uri: Optional[str] = "",
        subject: Optional[str] = "",
        override_access_lifespan: Optional[pendulum.Duration] = None,
        custom_token: str = "",
    ) -> dict:
        """
        Sends an email to a user, containing a time expiring
        token usable for several actions.  This requires
        your application is initialized with a `mail` extension,
        which supports sanic-mailing's :py:class:`Message` object and
        a :py:meth:`send_message` method.

        Args:
            user (:py:class:`User`):  The user object to tie claim to (username, id, email, etc)
            email (str): The email address to attempt to send to.
            template (Optional, :py:data:`filehandle`): HTML Template for the email.
                If not provided, a stock entry is used.
            action_sender (str): The sender that should be attached to the email.
            action_uri (str): The uri that should be visited to complete this notification
                action.
            subject (str): The email subject.
            override_access_lifespan (Optional, :py:data:`pendulum`): Overrides the
                :py:data:`TOKEN_ACCESS_LIFESPAN` to set an access lifespan for the registration token.
                Defaults to :py:data:`TOKEN_ACCESS_LIFESPAN` config setting.
            custom_token (str): The token to be carried as the email's payload.

        Returns:
            dict: Summary of information sent, along with the `result` from mail send. (Essentially
            the response of :py:func:`send_token_email`).

        Raises:
            :py:exc:`~sanic_beskar.exceptions.BeskarError`: Missing required parameters.

        """
        notification = {
            "result": None,
            "message": None,
            "user": str(user),
            "email": email,
            "token": custom_token,
            "subject": subject,
            "confirmation_uri": action_uri,  # backwards compatibility
            "action_uri": action_uri,
        }

        BeskarError.require_condition(
            self.app.ctx.mail,
            "Your app must have a mail extension enabled to register by email",
        )

        BeskarError.require_condition(
            action_sender,
            "A sender is required to send confirmation email",
        )

        BeskarError.require_condition(
            custom_token,
            "A custom_token is required to send notification email",
        )

        if template is None:
            async with aiofiles.open(self.confirmation_template, mode="r") as fh:
                template = await fh.read()

        with BeskarError.handle_errors("fail sending email"):
            jinja_tmpl = jinja2.Template(template, autoescape=True, enable_async=True)
            notification["message"] = (await jinja_tmpl.render_async(notification)).strip()

            logger.debug(f"Sending email to {email}")
            notification["result"] = await self.app.ctx.mail.send_message(
                subject=notification["subject"],
                to=[notification["email"]],
                from_address=action_sender,
                html=notification["message"],
                reply_to=action_sender
            )

        return notification

    async def get_user_from_registration_token(self, token: str) -> Any:
        """
        Gets a user based on the registration token that is supplied. Verifies
        that the token is a registration token and that the user can be properly
        retrieved

        Args:
            token (str): Registration token to validate.

        Returns:
            :py:class:`User`: :py:class:`User` object of looked up user after token validation
        """

        data = await self.extract_token(token, access_type=AccessType.register)
        user_id = data.get("id")
        BeskarError.require_condition(
            user_id is not None,
            "Could not fetch an id from the registration token",
        )
        user = await self.user_class.identify(user_id)
        BeskarError.require_condition(
            user is not None,
            "Could not identify the user from the registration token",
        )
        return user

    async def validate_reset_token(self, token: str) -> Any:
        """
        Validates a password reset request based on the reset token
        that is supplied. Verifies that the token is a reset token
        and that the user can be properly retrieved

        Args:
            token (str): Reset token to validate.

        Returns:
            :py:class:`User`: object of looked up user after token validation

        Raises:
            :py:exc:`~sanic_beskar.exceptions.BeskarError`: Missing required parameters
        """

        data = await self.extract_token(token, access_type=AccessType.reset)
        user_id = data.get("id")
        BeskarError.require_condition(
            user_id is not None,
            "Could not fetch an id from the reset token",
        )
        user = await self.user_class.identify(user_id)
        BeskarError.require_condition(
            user is not None,
            "Could not identify the user from the reset token",
        )
        return user

    def hash_password(self, raw_password: str) -> str:
        """
        Hashes a plaintext password using the stored passlib password context

        Args:
            raw_password (str): cleartext password for the user

        Returns:
            str: Properly hashed ciphertext of supplied :py:data:`raw_password`

        Raises:
            :py:exc:`~sanic_beskareptions.BeskarError`: No password is provided
        """

        BeskarError.require_condition(
            self.pwd_ctx is not None,
            "Beskar must be initialized before this method is available",
        )
        """
        `scheme` is now set with self.pwd_ctx.update(default=scheme) due
            to the depreciation in upcoming passlib 2.0.
         zillions of warnings suck.
        """
        return self.pwd_ctx.hash(raw_password)

    async def verify_and_update(self, user: Any, password: str = "") -> Any:
        """
        Validate a password hash contained in the user object is
        hashed with the defined hash scheme (:py:data:`BESKAR_HASH_SCHEME`).

        If not, raise an Exception of :py:exc:`~sanic_beskar.exceptions.LegacySchema`,
        unless the :py:data:`password` argument is provided, in which case an updated
        :py:class:`User` will be returned, and must be saved by the calling app. The
        updated :py:class:`User` will contain the users current password updated to the
        currently desired hash scheme (:py:exc:`~BESKAR_HASH_SCHEME`).

        Args:
            user (:py:class:`User`): The user class to tie claim to (username, id,
                email, etc). *MUST* include the password field, defined as :py:attr:`password`.
            password (str): The user's provide password from login.  If present, this is used
                to validate and then attempt to update with the new :py:data:`BESKAR_HASH_SCHEME`
                scheme.

        Returns:
            :py:class:`User`: Authenticated :py:class:`User`

        Raises:
            :py:exc:`~sanic_beskar.exceptions.AuthenticationError`: Authentication failure
        """

        if self.pwd_ctx.needs_update(user.password):
            if password:
                (rv, updated) = self.pwd_ctx.verify_and_update(
                    password,
                    user.password,
                )
                AuthenticationError.require_condition(
                    rv,
                    "Could not verify password",
                )
                user.password = updated
            else:
                used_hash = self.pwd_ctx.identify(user.password)
                desired_hash = self.hash_scheme
                raise LegacyScheme(
                    f"Hash using non-current scheme '{used_hash}'." f"Use '{desired_hash}' instead."
                )

        return user
