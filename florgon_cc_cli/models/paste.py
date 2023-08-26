"""
    Paste TypedDict model from CC API responses.
"""
from typing import TypedDict, Optional


class PasteLink(TypedDict):
    """
    Single paste link.
    """

    href: str


class PasteLinks(TypedDict):
    """
    Paste links in paste field `_links`.
    """

    stats: PasteLink


class Paste(TypedDict):
    """
    Paste model from API.
    """

    id: int
    text: str
    hash: str
    lang: str
    expires_at: float
    is_expired: bool
    stats_is_public: bool
    is_deleted: bool
    burn_after_read: bool
    _links: Optional[PasteLinks]
