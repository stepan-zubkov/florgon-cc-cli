"""
    Services for working with single paste API or list.
"""

from typing import Optional, Tuple, Union, NoReturn, List, Literal

import click
import re
from pick import pick

from florgon_cc_cli.models.url import Url
from florgon_cc_cli.services.api import (
    execute_json_api_method,
    execute_api_method,
    try_decode_response_to_json,
)
from florgon_cc_cli import config
from florgon_cc_cli.models.paste import Paste
from florgon_cc_cli.models.error import Error
from florgon_cc_cli.models.stats import Stats


def build_paste_open_url(hash: str) -> str:
    """Builds url for opening paste."""
    return f"{config.URL_PASTE_OPEN_PROVIDER}/{hash}"


def create_paste(
    text: str,
    *,
    lang: Optional[str],
    stats_is_public: bool = False,
    burn_after_read: bool = False,
    access_token: Optional[str] = None,
) -> Union[Tuple[Literal[True], Paste], Tuple[Literal[False], Error]]:
    """
    Creates paste from text.
    :param str text: paste text
    :param str lang: programming language of paste
    :param Optional[str] access_token: Florgon OAuth token that used for authorization.
                                     Defaults to None
    :param bool stats_is_public: makes url stats public for all users
    :param bool burn_after_read: paste will be deleted after first reading
    :return: Tuple with two elements.
             First is a creaton status (True if successfully).
             Seconds is a response body.
    :rtype: Tuple[True, Paste] if request is successfully, else Tuple[False, Error]
    """
    response = execute_json_api_method(
        "POST",
        "pastes/",
        data={
            "text": text,
            "lang": lang,
            "stats_is_public": stats_is_public,
            "burn_after_read": burn_after_read,
        },
        access_token=access_token,
    )
    if "success" in response:
        response["success"]["paste"]["text"] = response["success"]["paste"]["text"].replace(
            "\\n", "\n"
        )
        return True, response["success"]["paste"]
    return False, response["error"]


def get_pastes_list(
    access_token: Optional[str] = None,
) -> Union[Tuple[Literal[True], List[Paste]], Tuple[Literal[False], Error]]:
    """
    Returns list of user pastes by access_token.
    :param Optional[str] access_token: Florgon OAuth token that used for authorization.
                                       Defaults to None.
    :rtype: Tuple[True, Paste] if successfully, else Tuple[False, Error]
    :return: Tuple with two elements.
             First is a response status (True if successfully).
             Seconds is a response body.
    """
    response = execute_json_api_method(
        "GET",
        "pastes/",
        access_token=access_token,
    )
    if "success" in response:
        pastes: List[Paste] = []
        for paste in response["success"]["pastes"]:
            # NOTE: This is temporary solution. Should be moved to cc-api.
            if not paste["is_deleted"]:
                paste["text"] = paste["text"].replace("\\n", "\n")
                pastes.append(paste)
        return True, pastes
    return False, response["error"]


def request_hash_from_pastes_list(access_token: Optional[str] = None) -> Union[str, NoReturn]:
    """
    Requests server for pastes list and requests user to choose one.
    :param str access_token: Access token
    :returns: Paste hash
    :rtype: str
    """
    success, response = get_pastes_list(access_token=access_token)
    if not success:
        click.secho(response["message"], err=True, fg="red")
        click.get_current_context().exit(1)

    # TODO: This logic must be moved to API
    pastes = [paste for paste in response if not paste["is_expired"] and not paste["is_deleted"]]
    if not pastes:
        click.secho("You have not active pastes!", fg="red", err=True)
        click.get_current_context().exit(1)

    nl = "\n"
    pastes_formatted = [
        f"{build_paste_open_url(paste['hash'])} - {paste['text'].split(nl)[0][:50] + '...'}"
        for paste in pastes
    ]
    _, index = pick(pastes_formatted, "Choose one from your pastes:", indicator=">")
    return pastes[index]["hash"]


def extract_hash_from_paste_short_url(short_url: str) -> Union[str, NoReturn]:
    """
    Extracts hash from paste short url.
    :param str short_url: paste short url
    :rtype: Union[str, NoReturn]
    :return: paste hash or exit application
    """
    short_url_hashes = re.findall(
        f"^{config.URL_PASTE_OPEN_PROVIDER}" + r"/([a-zA-Z0-9]{6})$", short_url
    )
    if not short_url_hashes:
        click.secho(
            f"Short url is invalid! It should be in form '{config.URL_PASTE_OPEN_PROVIDER}/xxxxxx'",
            err=True,
            fg="red",
        )
        click.get_current_context().exit(1)

    return short_url_hashes[0]


def get_paste_info_by_hash(hash: str) -> Tuple[bool, Union[Url, Error]]:
    """
    Returns info about paste short url by hash.
    :param str hash: short url hash
    :return: Tuple with two elements.
             First is a response status (True if successfully).
             Seconds is a response body.
    :rtype: Tuple[True, Url] if request is successfully, else Tuple[True, Error]
    """
    response = execute_json_api_method("GET", f"pastes/{hash}/")
    if "success" in response:
        response["success"]["paste"]["text"] = response["success"]["paste"]["text"].replace(
            "\\n", "\n"
        )
        return True, response["success"]["paste"]
    return False, response["error"]


def delete_paste_by_hash(
    hash: str, access_token: Optional[str] = None
) -> Union[Tuple[bool, Optional[Error]], NoReturn]:
    """
    Deletes user's paste by access_token.
    :param str hash: paste hash
    :param Optional[str] access_token: access token
    :return: Tuple with two or one elements.
             First is a deletion status (True if successfully).
             Seconds is a response body (if error).
    :rtype: Tuple[True] if successfully deleted, Tuple[False, Error] if error occured,
            or exit application if cannot decode to json
    """
    response = execute_api_method("DELETE", f"pastes/{hash}/", access_token=access_token)
    if response.status_code == 204:
        return (True,)
    return try_decode_response_to_json(response)


def get_paste_stats_by_hash(
    hash: str,
    url_views_by_referers_as: str = "percent",
    url_views_by_dates_as: str = "percent",
    access_token: Optional[str] = None,
) -> Union[Tuple[Literal[True], Stats], Tuple[Literal[False], Error], NoReturn]:
    """
    Returns statistics about paste by hash.
    :param str hash: paste hash
    :return: Tuple with two elements.
             First is a response status (True if successfully).
             Seconds is a response body.
    :rtype: Tuple[True, Stats] if response requested successfully, Tuple[False, Error] if error occured,
            or exit application if cannot decode response to json
    """
    response = execute_json_api_method(
        "GET",
        f"pastes/{hash}/stats",
        params={
            "referer_views_value_as": url_views_by_referers_as,
            "dates_views_value_as": url_views_by_dates_as,
        },
        access_token=access_token,
    )
    if "success" in response:
        return True, response["success"]["views"]
    return False, response["error"]


def clear_paste_stats_by_hash(
    hash: str, access_token: Optional[str] = None
) -> Union[Tuple[Literal[True]], Tuple[Literal[False], Error], NoReturn]:
    """
    Clears user's paste stats by access_token.
    :param str hash: paste hash
    :param Optional[str] access_token: access token
    :return: Tuple with two or one elements.
             First is a clearsing status (True if successfully).
             Seconds is a response body (if error).
    :rtype: Tuple[True] if successfully cleared, Tuple[False, Error] if error occured,
            or exit application if cannot decode to json
    """
    response = execute_api_method("DELETE", f"pastes/{hash}/stats", access_token=access_token)
    if response.status_code == 204:
        return (True,)
    return try_decode_response_to_json(response)


def edit_paste_by_hash(
    hash: str, text: str, access_token: Optional[str] = None
) -> Union[Tuple[Literal[True], Paste], Tuple[Literal[False], Error], NoReturn]:
    """
    Edits user's paste text by hash
    :param str hash: paste hash
    :param str text: new paste text
    :param Optional[str] access_token: access token
    :return: Tuple with two or one elements.
             First is a response status (True if successfully).
             Seconds is a response body.
    :rtype: Tuple[True, Paste] if successfully edited, Tuple[False, Error] if error occured,
            or exit application if cannot decode to json
    """
    response = execute_json_api_method(
        "PATCH", f"pastes/{hash}/", access_token=access_token, data={"text": text}
    )
    if "success" in response:
        return True, response["success"]["paste"]
    return False, response["error"]
