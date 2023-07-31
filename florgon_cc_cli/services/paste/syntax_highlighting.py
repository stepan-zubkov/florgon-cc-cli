"""
    Module for paste's syntax highlighting. It works only if paste's lang param is 'plain'.
"""
from pygments.formatters import TerminalFormatter
from pygments.lexers import get_lexer_by_name
from pygments import highlight


def get_highlighted_code(text: str, lang: str) -> str:
    """
    Returns highlighted code using ANSI escape color sequences.
    :param str text: text to highlight
    :param str lang: programming language
    """
    return highlight(text, get_lexer_by_name(lang), TerminalFormatter())
