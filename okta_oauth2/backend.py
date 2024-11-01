from django.contrib.auth.backends import ModelBackend

from .conf import Config
from .tokens import TokenValidator

config = Config()


class OktaBackend(ModelBackend):
    """
    Uses the same user store as the django ModelBackend but actually
    does its authentication using Okta's OIDC authorization servers.

    The Okta sign in widget will accept a username and password,
    validate them, and if successful return an authorization code.

    We take that code and use it to obtain an Access Token, an
    ID Token and a Refresh Token from Okta, set them in the session,
    and get the user from the Django database.
    """

    def authenticate(
        self, request, code=None, interaction_code=None, code_verifier=None, **kwargs
    ):
        if code is None and interaction_code is None:
            return
        if interaction_code and code_verifier is None:
            return

        validator = TokenValidator(config, request)
        if interaction_code:
            user, tokens = validator.tokens_from_auth_interaction_code(
                interaction_code, code_verifier
            )
        else:
            user, tokens = validator.tokens_from_auth_code(code)

        if self.user_can_authenticate(user):
            return user
