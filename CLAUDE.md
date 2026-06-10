# re-pcap

MCP server for packet-capture analysis: PCAP parse, HTTP/HTTPS extract, DNS query extraction, publisher-endpoint correlation. Pure-Python, vendor-neutral.

Version: 0.1.0 | License: MIT

## Structure

```
re-pcap/
  pyproject.toml                    # build config (setuptools, mcp[cli] + deps)
  src/re_pcap/
    __init__.py
    __main__.py                     # entry: from server import main; main()
    server.py                       # FastMCP app with @mcp.tool() functions
  README.md
  LICENSE
  SECURITY.md


```

## Build

```bash
pip install -e .                    # install with deps
re-pcap                         # start MCP server on stdio
```



## Tools

This server exposes these MCP tools: `check_pcap,parse_pcap,filter_flows,extract_http_https,extract_dns_queries,correlate_endpoints`

## Usage (standalone)

Register this server in your `.mcp.json`:

```json
{
  "mcpServers": {
    "re-pcap": {
      "command": "uv",
      "args": ["--directory", "/path/to/re-pcap", "run", "re-pcap"]
    }
  }
}
```

Or use via the [RE-AI agent-space](https://github.com/Heretek-RE/RE-AI): `./install.sh` clones all servers at pinned versions.
