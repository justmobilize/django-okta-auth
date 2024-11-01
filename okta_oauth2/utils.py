import base64
import hashlib
import logging
import random
import string

from django.contrib import messages
from django.contrib.messages.api import MessageFailure
from django.core.cache import caches
from django.http import HttpResponseRedirect, HttpResponseServerError
from django.urls import reverse

logger = logging.getLogger(__name__)


def create_code_verifier():
    length = random.randint(43, 128)
    charset = string.ascii_letters + string.digits + "_"
    return "".join(random.choice(charset) for _ in range(length))


def create_code_challenge(code_verifier):
    hash_digest = hashlib.sha256(code_verifier.encode()).digest()
    return base64.urlsafe_b64encode(hash_digest).rstrip(b"=").decode()


def create_state():
    return "".join(random.choice(string.ascii_letters) for _ in range(40))


def set_state(config, state, value):
    cache = caches[config.cache_alias]
    cache_key = "{}-states-{}".format(config.cache_prefix, state)
    cache.set(cache_key, value, 60 * 10)


def get_state(config, state):
    cache = caches[config.cache_alias]
    cache_key = "{}-states-{}".format(config.cache_prefix, state)
    value = cache.get(cache_key)
    cache.delete(cache_key)
    return value


def return_error(request, error_description):
    try:
        messages.error(request, error_description)
    except MessageFailure:
        return HttpResponseServerError(error_description)
    return HttpResponseRedirect(reverse("okta_oauth2:login"))
