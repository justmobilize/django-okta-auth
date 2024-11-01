import re

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.urls import NoReverseMatch, reverse
from jwt.algorithms import get_default_algorithms

# We can't check for tokens on these URL's
# because we won't have them.
DEFAULT_PUBLIC_NAMED_URLS = (
    "okta_oauth2:login",
    "okta_oauth2:logout",
    "okta_oauth2:callback",
)


class Config:
    def __init__(self):
        try:
            # Configuration object
            self.org_url = settings.OKTA_AUTH["ORG_URL"]
            # Make users in this okta group superusers
            self.superuser_group = settings.OKTA_AUTH.get("SUPERUSER_GROUP", None)
            # Make users in this okta group staff
            self.staff_group = settings.OKTA_AUTH.get("STAFF_GROUP", None)
            # Allow django-okta-auth to add groups
            self.manage_groups = settings.OKTA_AUTH.get("MANAGE_GROUPS", False)
            # Timeout in seconds for requests to Okta
            self.request_timeout = settings.OKTA_AUTH.get("REQUEST_TIMEOUT", 10)

            # OpenID Specific
            self.client_id = settings.OKTA_AUTH["CLIENT_ID"]
            self.client_secret = settings.OKTA_AUTH["CLIENT_SECRET"]
            self.issuer = settings.OKTA_AUTH["ISSUER"]
            self.scopes = settings.OKTA_AUTH.get(
                "SCOPES", "openid profile email offline_access"
            )
            self.redirect_uri = settings.OKTA_AUTH["REDIRECT_URI"]
            self.login_redirect_url = settings.OKTA_AUTH.get("LOGIN_REDIRECT_URL", "/")

            # OKTA mode
            self.use_classic_engine = settings.OKTA_AUTH.get(
                "USE_CLASSIC_ENGINE", False
            )

            # Django Specific
            self.cache_prefix = settings.OKTA_AUTH.get("CACHE_PREFIX", "okta")
            self.cache_alias = settings.OKTA_AUTH.get("CACHE_ALIAS", "default")
            self.cache_timeout = settings.OKTA_AUTH.get("CACHE_TIMEOUT", 600)
            self.use_username = settings.OKTA_AUTH.get("USE_USERNAME", False)
            self.public_urls = self.build_public_urls()

            # Django Template
            self.include_admin_template_vars = settings.OKTA_AUTH.get(
                "INCLUDE_ADMIN_TEMPLATE_VARS", False
            )

        except (AttributeError, KeyError):
            raise ImproperlyConfigured("Missing Okta authentication settings")

    def build_public_urls(self):
        named_urls = []

        # Get any user-specified named urls and concat the default named urls
        # so that we can reverse them all at once.
        public_named_urls = (
            settings.OKTA_AUTH.get("PUBLIC_NAMED_URLS", ()) + DEFAULT_PUBLIC_NAMED_URLS
        )

        for name in public_named_urls:
            try:
                named_urls.append(reverse(name))
            except NoReverseMatch:
                pass

        # Concatenate user-specified regex URL's with a tuple of reversed named
        # url's that have been converted to a regex, so we can use a regex
        # to match against a url in every case.
        public_urls = tuple(settings.OKTA_AUTH.get("PUBLIC_URLS", ())) + tuple(
            ["^%s$" % url for url in named_urls]
        )

        return [re.compile(u) for u in public_urls]
