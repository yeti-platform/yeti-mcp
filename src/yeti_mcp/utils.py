import functools
import os
import logging

from yeti.api import YetiApi

logger = logging.getLogger(__name__)


@functools.cache
def get_yeti_client() -> YetiApi:
    """
    Get a cached instance of the YetiApi client.
    This is used to avoid creating multiple instances of the client.
    """
    yeti_endpoint = os.environ.get("YETI_ENDPOINT")
    yeti_api_key = os.environ.get("YETI_API_KEY")
    if not yeti_endpoint or not yeti_api_key:
        logger.error("YETI_ENDPOINT and YETI_API_KEY environment variables must be set")
        raise ValueError("Missing Yeti API configuration")
    yeti_client = YetiApi(yeti_endpoint)
    yeti_client.auth_api_key(yeti_api_key)
    return yeti_client
