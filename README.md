# gemini3-agent-proxy
Lightweight Python proxy to fix the "missing thought_signature" error when using Gemini 3.0 Flash in Agentic workflows (e.g., with Continue.dev, Cursor, or Aider).

# The Problem

Google's Gemini API recently introduced a mandatory thought_signature for function calls (tool use). Many IDE plugins do not yet correctly persist this signature across the request loop, causing agentic tasks (like @codebase or shell execution) to fail.

# The Solution

This proxy:
    Captures the thought_signature from Google's streaming response.
    Automatically injects the last valid signature into the next functionCall request.
    Acts as a bridge between your IDE and Google, ensuring the Agent loop stays unbroken.

## Setup
1. **Install dependencies:**
```bash
   pip install flask requests
```
2. **Set API KEY Windows:**
```bash
    set GEMINI_API_KEY='your-api-key'
```
4. **Start Proxy**
```bash
   python main.py
```

# IDE Configuration (Example: Continue.dev)
```json
{
  "models": [
    {
      "title": "Gemini 3.0 Flash (via Proxy)",
      "provider": "gemini",
      "model": "gemini-1.5-flash",
      "apiBase": "http://localhost:5005"
    }
  ]
}
```
