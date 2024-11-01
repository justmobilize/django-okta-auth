import logging

from django.contrib import admin
from django.contrib.auth import authenticate, login as auth_login, logout as auth_logout
from django.http import HttpResponseBadRequest, HttpResponseRedirect
from django.shortcuts import redirect, render
from django.urls import reverse
from django.urls.exceptions import NoReverseMatch

from .conf import Config
from .utils import (
    create_code_challenge,
    create_code_verifier,
    create_state,
    get_state,
    return_error,
    set_state,
)

logger = logging.getLogger(__name__)


def login(request):
    config = Config()

    state = create_state()
    state_data = {"valid": True}

    okta_config = {
        "clientId": config.client_id,
        "issuer": config.issuer,
        "redirectUri": str(config.redirect_uri),
        "scope": config.scopes,
        "state": state,
        "url": config.org_url,
        "useClassicEngine": config.use_classic_engine,
    }
    if not config.use_classic_engine:
        code_verifier = create_code_verifier()
        code_challenge = create_code_challenge(code_verifier)
        state_data["code_verifier"] = code_verifier
        okta_config["codeChallenge"] = code_challenge

    set_state(config, state, state_data)

    context = {
        "config": okta_config,
    }

    if config.include_admin_template_vars:
        context.update(
            {
                "site_header": admin.site.site_header,
                "site_title": admin.site.site_title,
                "admin_login": reverse("admin:login"),
                "title": "Log In",
            }
        )

    return render(request, "okta_oauth2/login.html", context)


def callback(request):
    config = Config()

    if request.method == "POST":
        return HttpResponseBadRequest("Method not supported")

    error_description = None
    if "error" in request.GET:
        error_description = request.GET.get(
            "error_description", "An unknown error occurred."
        )
        return return_error(request, error_description)

    state = request.GET["state"]
    state_data = get_state(config, state)
    if not isinstance(state_data, dict) or not state_data["valid"] is True:
        error_description = "Unknown state, please try again"
        return return_error(request, error_description)

    if config.use_classic_engine:
        code = request.GET["code"]
        user = authenticate(request, code=code)
    else:
        interaction_code = request.GET["interaction_code"]
        code_verifier = state_data["code_verifier"]
        user = authenticate(
            request, interaction_code=interaction_code, code_verifier=code_verifier
        )

    if user is None:
        return return_error(request, error_description)

    auth_login(request, user)

    try:
        redirect_url = reverse(config.login_redirect_url)
    except NoReverseMatch:
        redirect_url = config.login_redirect_url

    return redirect(redirect_url)


def logout(request):
    auth_logout(request)
    return HttpResponseRedirect(reverse("okta_oauth2:login"))
