"""Fixed stdio MCP interface for target reads; no shell, filesystem, or provider access."""
import json
import sys
from .fetch import fetch

TOOL = {"name":"target_fetch","description":"Read a scoped registered target with GET or HEAD only.","inputSchema":{"type":"object","properties":{"url":{"type":"string"},"method":{"type":"string","enum":["GET","HEAD"]}},"required":["url"],"additionalProperties":False}}

def main():
    for line in sys.stdin:
        value = None
        try:
            value=json.loads(line)
            if "id" not in value:
                continue
            method=value.get("method")
            if method=="initialize":
                result={"protocolVersion":"2024-11-05","capabilities":{"tools":{}},"serverInfo":{"name":"numen-target","version":"0.1.0"}}
            elif method=="tools/list":
                result={"tools":[TOOL]}
            elif method=="tools/call" and value.get("params",{}).get("name")=="target_fetch":
                args=value["params"].get("arguments",{})
                result={"content":[{"type":"text","text":json.dumps(fetch(args["url"],args.get("method","GET")))}]}
            elif method=="ping":
                result={}
            else:
                raise ValueError("unknown method")
            print(json.dumps({"jsonrpc":"2.0","id":value["id"],"result":result}),flush=True)
        except Exception:
            if isinstance(value,dict) and "id" in value:
                print(json.dumps({"jsonrpc":"2.0","id":value["id"],"error":{"code":-32602,"message":"Scoped target operation denied or unavailable"}}),flush=True)

if __name__=="__main__":
    main()
