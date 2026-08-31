"""Black Noir CLI - a deep-search OSINT AI agent.

Two intelligence surfaces:
  * Public surface  -> DuckDuckGo, Bing
  * Dark web surface -> clearnet-accessible index/aggregator frontends only
                        (Ahmia, Torch, Haystak, OnionLand, OnionSearch,
                         dark-web-scraper, Telepathy, Lyzem, Telegago,
                         Have I Been Pwned, DeHashed)

The agent NEVER connects to a Tor/onion service, downloads files, or follows
untrusted links. It only *reads what indexes already expose* and reasons over it.
"""

__version__ = "1.0.0"
__all__ = ["__version__"]
