"""
    Module for paste's syntax highlighting. It works only if paste's lang param is 'plain'.
"""
import click
from pygments.formatters import TerminalFormatter
from pygments.lexers import get_lexer_by_name
from pygments import highlight
from pygments.util import ClassNotFound


def get_highlighted_code(text: str, lang: str) -> str:
    """
    Returns highlighted code using ANSI escape color sequences.
    :param str text: text to highlight
    :param str lang: programming language
    """
    if lang in ("plain", "plaintext"):
        return text
    try:
        lexer = get_lexer_by_name(lang)
    except ClassNotFound:
        click.secho(f"Language {lang} is not supported by this client!", fg="bright_yellow")
        return text
    return highlight(text, lexer, TerminalFormatter())
