# re-pcap

MCP server for packet-capture analysis: PCAP parse, HTTP/HTTPS extract, DNS query extraction, publisher-endpoint correlation. Pure-Python, vendor-neutral.

## Tools

Run ``re-pcap`` over the MCP stdio transport to expose the
tool surface. The server is a pure-Python wrapper; the actual
work delegates to the existing RE-AI servers (re-lief, re-rizin,
re-yara, re-frida, etc.).

## Installation

The server is installed by `./install.sh` from the plugin root
and is auto-registered in `.mcp.json`. No external system
dependencies.

## Vendor-neutrality

All output is vendor-neutral: category names only, no specific
commercial product / publisher / game title.
