"""
    Pastes management command.
"""
from io import TextIOWrapper
from datetime import datetime
from typing import List, Optional
import subprocess

import click

from florgon_cc_cli.services.config import get_access_token
from florgon_cc_cli.services.paste import (
    build_paste_open_url,
    create_paste,
    get_pastes_list,
    request_hash_from_pastes_list,
    get_paste_info_by_hash,
    delete_paste_by_hash,
    extract_hash_from_paste_short_url,
    get_paste_stats_by_hash,
    clear_paste_stats_by_hash,
    edit_paste_by_hash,
)
from florgon_cc_cli.services.files import concat_files
from florgon_cc_cli import config


@click.group()
def paste():
    """
    Command that interacts with single paste or list.
    """


@paste.command()
@click.option("-o", "--only-url", is_flag=True, default=False, help="Outputs single url to paste.")
@click.option(
    "-d", "--do-not-save", is_flag=True, default=False, help="Do not save paste in local history."
)
@click.option(
    "-s",
    "--stats-is-public",
    is_flag=True,
    default=False,
    help="Make paste stats public. Auth required.",
)
@click.option(
    "-b",
    "--burn-after-read",
    is_flag=True,
    default=False,
    help="Deletes paste after first reading.",
)
@click.option(
    "-f",
    "--from-file",
    "from_files",
    type=click.File("r"),
    multiple=True,
    help="Read paste from file.",
)
@click.option("-t", "--text", type=str, help="Paste text.")
def create(
    only_url: bool,
    do_not_save: bool,
    stats_is_public: bool,
    burn_after_read: bool,
    text: Optional[str],
    from_files: List[TextIOWrapper],
):
    """
    Creates paste from text or file.
    """
    if from_files and text:
        click.secho("Pass --from-file or --text, but not both!", fg="red", err=True)
        return
    if not from_files and not text:
        click.secho("Pass --from-file or --text!", fg="red", err=True)
        return
    if from_files:
        text = concat_files(from_files)

    access_token = get_access_token()
    if stats_is_public and access_token is None:
        click.secho("Auth required for --stats-is-public flag!", fg="red", err=True)
        return

    success, response = create_paste(
        text,
        stats_is_public=stats_is_public,
        burn_after_read=burn_after_read,
        access_token=access_token,
    )
    if not success:
        click.secho(response["message"], err=True, fg="red")
        return

    short_url = build_paste_open_url(response["hash"])
    if only_url:
        click.echo(short_url)
        return

    click.echo("Short url: " + click.style(short_url, fg="green"))
    click.echo(f"Text: \n{response['text']}")
    if response["burn_after_read"]:
        click.secho("This paste will burn after reading!", fg="bright_yellow")
    click.echo(f"Expires at: {datetime.fromtimestamp(response['expires_at'])}")
    if response["stats_is_public"]:
        click.echo("Stats is public")


@paste.command()
@click.option(
    "-e", "--exclude-expired", is_flag=True, default=False, help="Do not show expired pastes."
)
def list(exclude_expired: bool):
    """
    Prints a list of your pastes. Auth expired.
    """
    success, response = get_pastes_list(access_token=get_access_token())
    if not success:
        click.secho(response["message"], err=True, fg="red")
        return

    click.echo("Your pastes:")
    for paste in response:
        # NOTE: This is temporary solution. Should be moved to cc-api.
        if paste["is_expired"] and exclude_expired:
            continue

        text_preview = paste["text"].split("\n")[0][:50] + "..."
        if paste["is_expired"]:
            click.secho(
                f"{build_paste_open_url(paste['hash'])} - {text_preview} (expired)", fg="red"
            )
        else:
            click.echo(f"{build_paste_open_url(paste['hash'])} - {text_preview}")


@paste.command()
@click.option("-s", "--short_url", type=str, help="Short url.")
@click.option("-o", "--only-text", is_flag=True, default=False, help="Prints only paste text.")
def read(short_url, only_text):
    """
    Prints text and info about paste.
    If short url is not passed, you can choose it from your pastes interactively.
    """
    if short_url:
        short_url_hash = extract_hash_from_paste_short_url(short_url)
    else:
        click.echo("Short url is not specified, requesting for list of your pastes.")
        short_url_hash = request_hash_from_pastes_list(access_token=get_access_token())

    success, response = get_paste_info_by_hash(short_url_hash)
    if not success:
        click.secho(response["message"], err=True, fg="red")
        return
    if only_text:
        click.echo("Text:\n" + response["text"].replace("\\n", "\n"))
        return
    click.echo(f"Expires at: {datetime.fromtimestamp(response['expires_at'])}")
    if response["stats_is_public"]:
        click.echo("Stats is public")
    if response["burn_after_read"]:
        click.secho("This paste will burn after reading!", fg="bright_yellow")
    click.echo("Text:\n" + response["text"].replace("\\n", "\n"))


@paste.command()
@click.option("-s", "--short-url", type=str, help="Short url.")
def delete(short_url: str):
    """
    Deletes paste. Auth Required.
    If short url is not passed, you can choose it from your pastes interactively.
    """
    if short_url:
        short_url_hash = extract_hash_from_paste_short_url(short_url)
    else:
        click.echo("Short url is not specified, requesting for list of your pastes.")
        short_url_hash = request_hash_from_pastes_list(access_token=get_access_token())

    success, *response = delete_paste_by_hash(
        hash=short_url_hash,
        access_token=get_access_token(),
    )
    if not success:
        click.secho(response[0]["message"], err=True, fg="red")
        return
    else:
        click.secho("Paste was successfully deleted!", fg="green")


@paste.command()
@click.option("-s", "--short-url", type=str, help="Short url.")
@click.option(
    "-r",
    "--referers-as",
    type=click.Choice(["percent", "number"]),
    default="percent",
    help="Paste views referers as.",
)
@click.option(
    "-d",
    "--dates-as",
    type=click.Choice(["percent", "number"]),
    default="percent",
    help="Paste views dates as.",
)
def stats(short_url: str, referers_as: str, dates_as: str):
    """
    Prints paste views statistics.
    If short url is not passed, you can choose it from your pastes interactively.
    """
    if short_url:
        paste_hash = extract_hash_from_paste_short_url(short_url)
    else:
        click.echo("Short url is not specified, requesting for list of your pastes.")
        paste_hash = request_hash_from_pastes_list(access_token=get_access_token())

    success, response = get_paste_stats_by_hash(
        paste_hash,
        url_views_by_referers_as=referers_as,
        url_views_by_dates_as=dates_as,
        access_token=get_access_token(),
    )
    if not success:
        click.secho(response["message"], err=True, fg="red")
        return

    click.echo("Total views: " + click.style(response["total"], fg="green"))
    if response.get("by_referers"):
        click.echo("Views by referers:")
        for referer in response["by_referers"]:
            click.echo(
                f"\t{referer} - {response['by_referers'][referer]}"
                + "%" * int(referers_as == "percent")
            )

    if response.get("by_dates"):
        click.echo("Views by dates:")
        for date in response["by_dates"]:
            click.echo(
                f"\t{date} - {response['by_dates'][date]}" + "%" * int(dates_as == "percent")
            )


@paste.command()
@click.option("-s", "--short-url", type=str, help="Short url.")
def clear_stats(short_url: str):
    """
    Clears paste stats. Auth required.
    If short url is not passed, you can choose it from your pastes interactively.
    """
    if short_url:
        short_url_hash = extract_hash_from_paste_short_url(short_url)
    else:
        click.echo("Short url is not specified, requesting for list of your pastes.")
        short_url_hash = request_hash_from_pastes_list(access_token=get_access_token())

    success, *response = clear_paste_stats_by_hash(
        hash=short_url_hash, access_token=get_access_token()
    )
    if not success:
        click.secho(response[0]["message"], err=True, fg="red")
        return

    click.secho("Paste stats was successfully cleared!", fg="green")


@paste.command()
@click.option("-s", "--short-url", type=str, help="Short url.")
@click.option(
    "-e",
    "--editor",
    type=str,
    envvar="EDITOR",
    prompt="Editor for paste",
    help="Open in specified editor. Defaults to EDITOR environment variable.",
)
def edit(short_url: str, editor: str):
    if short_url:
        short_url_hash = extract_hash_from_paste_short_url(short_url)
    else:
        click.echo("Short url is not specified, requesting for list of your pastes.")
        short_url_hash = request_hash_from_pastes_list(access_token=get_access_token())

    success, response = get_paste_info_by_hash(hash=short_url_hash)
    if not success:
        click.secho(response["message"], err=True, fg="red")
        return

    paste_filename = config.TEMP_FILES_DIR / f"florgon_cc_cli_paste_{short_url_hash}"
    with open(paste_filename, "w") as paste_file:
        paste_file.write(response["text"])

    process_result = subprocess.run([editor, paste_filename])
    if process_result.returncode != 0:
        click.secho(
            f"An error occured during editing the paste! Exit code: {process_result.returncode}"
        )

    with open(paste_filename, "r") as paste_file:
        new_text = paste_file.read()
    success, response = edit_paste_by_hash(hash=short_url_hash, text=new_text, access_token=get_access_token())
    if not success:
        click.secho(response["message"], err=True, fg="red")
        return

    click.secho("Paste was successfully edited!", fg="green")
