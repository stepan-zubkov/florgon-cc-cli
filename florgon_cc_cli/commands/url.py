"""
    Single url commands.
"""
from datetime import datetime

import click

from florgon_cc_cli.services.config import get_value_from_config, get_access_token
from florgon_cc_cli.services.url import (
    build_open_url,
    create_url,
    extract_hash_from_short_url,
    get_url_info_by_hash,
    get_url_stats_by_hash,
    get_urls_list,
    request_hash_from_urls_list,
    delete_url_by_hash,
    clear_url_stats_by_hash,
    delete_expired_urls,
)


@click.group()
def url():
    """Commands that interacts with single url or list."""


@url.command()
@click.option("-o", "--only-url", is_flag=True, default=False, help="Outputs single short url.")
@click.option(
    "-d", "--do-not-save", is_flag=True, default=False, help="Do not save url in local history."
)
@click.option(
    "-s",
    "--stats-is-public",
    is_flag=True,
    default=False,
    help="Make url stats public. Auth required.",
)
@click.argument("long_url", type=str)
def create(only_url: bool, do_not_save: bool, long_url: str, stats_is_public: bool):
    """Creates short url."""
    access_token = get_access_token()
    if stats_is_public and access_token is None:
        click.secho("Auth required for --stats-is-public flag!", fg="red", err=True)
        return

    success, response = create_url(
        long_url, stats_is_public=stats_is_public, access_token=access_token
    )
    if not success:
        click.secho(response["message"], err=True, fg="red")
        return

    short_url = build_open_url(response["hash"])
    if only_url:
        click.echo(short_url)
        return

    click.echo("Short url: " + click.style(short_url, fg="green"))
    click.echo(f"Redirects to: {response['redirect_url']}")
    click.echo(f"Expires at: {datetime.fromtimestamp(response['expires_at'])}")
    click.echo(f"QR Code url: {response['_links']['qr']['href']}")
    if response["stats_is_public"]:
        click.echo("Stats is public")


@url.command()
@click.option("-s", "--short-url", type=str, help="Short url.")
def info(short_url: str):
    """Prints main information about short url."""
    if short_url:
        short_url_hash = extract_hash_from_short_url(short_url)
    else:
        click.echo("Short url is not specified, requesting for list of your urls.")
        short_url_hash = request_hash_from_urls_list()

    success, response = get_url_info_by_hash(short_url_hash)
    if not success:
        click.secho(response["message"], err=True, fg="red")
        return

    click.echo("Redirects to: " + click.style(response["redirect_url"], fg="green"))
    click.echo(f"Expires at: {datetime.fromtimestamp(response['expires_at'])}")
    click.echo(f"QR Code url: {response['_links']['qr']['href']}")
    if response["stats_is_public"]:
        click.echo("Stats is public")


@url.command()
@click.option("-s", "--short-url", type=str, help="Short url.")
@click.option(
    "-r",
    "--referers-as",
    type=click.Choice(["percent", "number"]),
    default="percent",
    help="Url views referers as.",
)
@click.option(
    "-d",
    "--dates-as",
    type=click.Choice(["percent", "number"]),
    default="percent",
    help="Url views dates as.",
)
def stats(short_url: str, referers_as: str, dates_as: str):
    """Prints url views statistics."""
    if short_url:
        short_url_hash = extract_hash_from_short_url(short_url)
    else:
        click.echo("Short url is not specified, requesting for list of your urls.")
        short_url_hash = request_hash_from_urls_list()

    success, response = get_url_stats_by_hash(
        short_url_hash,
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


@url.command()
def list():
    """
    Prints list of your short urls. Auth required.
    """
    success, response = get_urls_list(access_token=get_access_token())
    if not success:
        click.secho(response["message"], err=True, fg="red")
        return

    click.echo("Your urls:")
    for url in response:
        if url["is_expired"]:
            click.secho(
                f"{build_open_url(url['hash'])} - {url['redirect_url']} (expired)", fg="red"
            )
        else:
            click.echo(f"{build_open_url(url['hash'])} - {url['redirect_url']}")


@url.command()
@click.option("-s", "--short-url", type=str, help="Short url.")
@click.option("-e", "--expired", is_flag=True, default=False, help="Delete all expired urls.")
def delete(short_url: str, expired: bool):
    """
    Deletes short url. Auth Required.
    """
    if expired:
        click.echo("Deleting all expired urls...")
        success, *response = delete_expired_urls(access_token=get_access_token())
        if not success:
            click.secho(response[0]["message"], err=True, fg="red")
            return
        click.secho("Successfully deleted all expired urls!", fg="green")
        return
    if short_url:
        short_url_hash = extract_hash_from_short_url(short_url)
    else:
        click.echo("Short url is not specified, requesting for list of your urls.")
        short_url_hash = request_hash_from_urls_list()

    success, *response = delete_url_by_hash(
        hash=short_url_hash,
        access_token=get_access_token(),
    )
    if not success:
        click.secho(response[0]["message"], err=True, fg="red")
        return

    click.secho("Url was successfully deleted!", fg="green")


@url.command()
@click.option("-s", "--short-url", type=str, help="Short url.")
def clear_stats(short_url: str):
    """
    Clears short url stats. Auth required.
    """
    if short_url:
        short_url_hash = extract_hash_from_short_url(short_url)
    else:
        click.echo("Short url is not specified, requesting for list of your urls.")
        short_url_hash = request_hash_from_urls_list()

    success, *response = clear_url_stats_by_hash(
        hash=short_url_hash, access_token=get_access_token()
    )
    if not success:
        click.secho(response[0]["message"], err=True, fg="red")
        return

    click.secho("Url stats was successfully cleared!", fg="green")
