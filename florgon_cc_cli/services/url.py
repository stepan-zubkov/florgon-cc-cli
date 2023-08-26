"""
    Services for working with single url API or list.
"""
import re
from typing import Tuple, Optional, Union, NoReturn, Literal, List

import click
from pick import pick

from florgon_cc_cli.services.api import (
    execute_json_api_method,
    execute_api_method,
    try_decode_response_to_json,
)
from florgon_cc_cli.services.config import get_value_from_config
from florgon_cc_cli.models.url import Url
from florgon_cc_cli.models.error import Error
from florgon_cc_cli import config


def build_open_url(hash: str) -> str:
    """Builds url for opening short url."""
    return f"{config.URL_OPEN_PROVIDER}/{hash}"


def create_url(
    long_url: str, stats_is_public: bool = False, access_token: Optional[str] = None
) -> Union[Tuple[Literal[True], Url], Tuple[Literal[False], Error]]:
    """
    Creates short url from long url.
    :param str long_url: url which short url will be redirect
    :param Optional[str] access_token: Florgon OAuth token that used for authentification.
                                     Defaults to None
    :param bool stats_is_public: makes url stats public for all users
    :return: Tuple with two elements.
             First is a creaton status (True if successfully).
             Seconds is a response body.
    :rtype: Tuple[True, Url] if request is successfully, else Tuple[False, Error]
    """
    response = execute_json_api_method(
        "POST",
        "urls/",
        data={"url": long_url, "stats_is_public": stats_is_public},
        access_token=access_token,
    )

    if "success" in response:
        return True, response["success"]["url"]
    return False, response["error"]


def get_url_info_by_hash(
    hash: str,
) -> Union[Tuple[Literal[True], Url], Tuple[Literal[False], Error]]:
    """
    Returns info about short url by hash.
    :param str hash: short url hash
    :return: Tuple with two elements.
             First is a response status (True if successfully).
             Seconds is a response body.
    :rtype: Tuple[True, Url] if request is successfully, else Tuple[True, Error]
    """
    response = execute_json_api_method("GET", f"urls/{hash}/")
    if "success" in response:
        return True, response["success"]["url"]
    return False, response["error"]


# No return type yet, `Stats` model need to be implemented
def get_url_stats_by_hash(
    hash: str,
    url_views_by_referers_as: str = "percent",
    url_views_by_dates_as: str = "percent",
    access_token: Optional[str] = None,
):
    """
    Returns statistics about short url by hash.
    :param str hash: short url hash
    :return: Tuple with two elements.
             First is a response status (True if successfully).
             Seconds is a response body.
    :rtype: Stats
    """
    response = execute_json_api_method(
        "GET",
        f"urls/{hash}/stats",
        params={
            "referer_views_value_as": url_views_by_referers_as,
            "dates_views_value_as": url_views_by_dates_as,
        },
        access_token=access_token,
    )
    if "success" in response:
        return True, response["success"]["views"]
    return False, response["error"]


def extract_hash_from_short_url(short_url: str) -> Union[str, NoReturn]:
    """
    Extracts hash from short url.
    :param str short_url: short url
    :rtype: Union[str, NoReturn]
    :return: url hash or exit application
    """
    short_url_hashes = re.findall(f"^{config.URL_OPEN_PROVIDER}" + r"/([a-zA-Z0-9]{6})$", short_url)
    if not short_url_hashes:
        click.secho(
            f"Short url is invalid! It should be in form '{config.URL_OPEN_PROVIDER}/xxxxxx'",
            err=True,
            fg="red",
        )
        click.get_current_context().exit(1)

    return short_url_hashes[0]


def request_hash_from_urls_list() -> Union[str, NoReturn]:
    success, response = get_urls_list(access_token=get_value_from_config("access_token"))
    if not success:
        click.secho(response["message"], err=True, fg="red")
        click.get_current_context().exit(1)

    # TODO: This logic must be moved to API
    urls = [url for url in response if not url["is_expired"] and not url["is_deleted"]]
    if not urls:
        click.secho("You have not active pastes!", fg="red", err=True)
        click.get_current_context().exit(1)

    urls_formatted = [f"{build_open_url(url['hash'])} - {url['redirect_url']}" for url in urls]
    _, index = pick(urls_formatted, "Choose one from your urls:", indicator=">")
    return urls[index]["hash"]


def get_urls_list(
    access_token: Optional[str] = None,
) -> Union[Tuple[Literal[True], List[Url]], Tuple[Literal[False], Error]]:
    """
    Returns user's urls by access_token.
    :param Optional[str] access_token: access token
    :return: Tuple with two elements.
             First is a creaton status (True if successfully).
             Seconds is a response body.
    :rtype: Tuple[True, Url] if request is successfully, else Tuple[False, Error]
    """
    response = execute_json_api_method("GET", "urls/", access_token=access_token)
    if "success" in response:
        # NOTE: This is temporary solution. Should be moved to cc-api.
        return True, [url for url in response["success"]["urls"] if not url["is_deleted"]]
    return False, response["error"]


def delete_url_by_hash(
    hash: str, access_token: Optional[str] = None
) -> Union[Tuple[Literal[True]], Tuple[Literal[False], Error], NoReturn]:
    """
    Deletes user's url by access_token.
    :param str hash: url hash
    :param Optional[str] access_token: access token
    :return: Tuple with two or one elements.
             First is a deletion status (True if successfully).
             Seconds is a response body (if error).
    :rtype: Tuple[True] if successfully deleted, Tuple[False, Error] if error occured,
            or exit application if cannot decode to json
    """
    response = execute_api_method("DELETE", f"urls/{hash}/", access_token=access_token)
    if response.status_code == 204:
        return (True,)
    return try_decode_response_to_json(response)


def clear_url_stats_by_hash(
    hash: str, access_token: Optional[str] = None
) -> Union[Tuple[Literal[True]], Tuple[Literal[False], Error], NoReturn]:
    """
    Clears user's url stats by access_token.
    :param str hash: url hash
    :param Optional[str] access_token: access token
    :return: Tuple with two or one elements.
             First is a clearsing status (True if successfully).
             Seconds is a response body (if error).
    :rtype: Tuple[True] if successfully cleared, Tuple[False, Error] if error occured,
            or exit application if cannot decode to json
    """
    response = execute_api_method("DELETE", f"urls/{hash}/stats", access_token=access_token)
    if response.status_code == 204:
        return (True,)
    return try_decode_response_to_json(response)
