"""The Seven Stones — OSS Free Edition ships three of them."""
from .amon_sul import AmonSulAgent
from .annuminas import AnnuminasAgent
from .ithil import IthilAgent

ALL_AGENTS = {
    "amon_sul":   AmonSulAgent,
    "annuminas":  AnnuminasAgent,
    "ithil":      IthilAgent,
}
