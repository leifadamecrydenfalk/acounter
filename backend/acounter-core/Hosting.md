Cloudflare Tunnels are an excellent way to securely expose your local services without opening firewall ports, and they can definitely handle routing traffic for both your backend API and your static frontend files.

Here's how you can modify your `config.yml` to achieve this:

1.  **API Rule First:** Define a rule specifically for your API endpoints (e.g., paths starting with `/api/`). This rule will proxy traffic to your Axum backend running on `https://127.0.0.1:3000`.
2.  **Frontend Rule Second:** Define a second rule for the *same hostname* but *without* a specific path (or with path `/`). This rule will serve static files directly from a local directory using `cloudflared`'s built-in file server functionality. This rule needs to come *after* the more specific API rule.
3.  **Catch-all Last:** Keep the final `http_status:404` rule.

**Modified `config.yml`:**

```yaml
# Tunnel UUID (replace with your actual UUID)
tunnel: 5e41bce4-2bfa-4095-94ef-609ac1a69127

# Path to the tunnel credentials file (adjust path if necessary)
credentials-file: ~/.cloudflared/5e41bce4-2bfa-4095-94ef-609ac1a69127.json

# Ingress rules define how traffic reaches your local services
# Rules are evaluated in order. The first match wins.
ingress:
  # Rule 1: Route API traffic (/api/*) to the Axum backend
  - hostname: acounter.net
    # Match requests specifically starting with /api/
    # Use path matching (simple prefix match is often enough)
    path: /api/.* # Regex to match /api/ followed by anything
    # Or just use prefix matching:
    # path: /api/
    service: https://127.0.0.1:3000
    originRequest:
      noTLSVerify: true # Keep this for your self-signed cert on localhost

  # Rule 2: Route all other traffic for acounter.net to the static frontend files
  - hostname: acounter.net
    # This rule acts as the fallback for acounter.net because it comes after
    # the /api/ rule and has no specific 'path' filter.
    # Use the 'file://' service to serve static files.
    # IMPORTANT: Replace '/path/to/your/frontend/dist' with the ACTUAL
    #            ABSOLUTE path to your frontend build output directory
    #            (where index.html, your .wasm, .js files live)
    #            on the machine running cloudflared.
    service: file:///path/to/your/frontend/dist
    # Example Linux path: file:///home/myuser/projects/acounter-frontend/dist
    # Example Windows path: file:///C:/Users/MyUser/Projects/acounter-frontend/dist

  # Rule 3 (Catch-all): Responds with 404 for any other traffic (recommended)
  # Handles requests to the tunnel UUID directly or other hostnames if configured.
  - service: http_status:404

# Optional: Specify the log file location and level
# logfile: /var/log/cloudflared.log
# loglevel: info
# Consider 'debug' level if troubleshooting ingress rules:
# loglevel: debug
```

**Explanation and Key Points:**

1.  **Rule Order:** The order is critical. `cloudflared` processes rules top-down. The `/api/` rule is checked first. If a request matches `acounter.net` and starts with `/api/`, it's sent to Axum.
2.  **API Path (`path: /api/.*` or `path: /api/`):**
    *   The `path` directive tells `cloudflared` to only apply this rule if the request path matches.
    *   Using a regex like `/api/.*` ensures it matches `/api/` and anything after it. Simple prefix matching `/api/` often works too.
    *   **Important:** Your Axum application's router should *expect* the `/api/` prefix in its routes (e.g., `.nest("/api", api_routes)` as shown previously). `cloudflared` typically *does not* strip the matched path prefix when proxying to an HTTP service.
3.  **Frontend Files (`service: file:///...`):**
    *   This tells `cloudflared` to act as a static file server for requests matching this rule (i.e., `acounter.net` requests that *don't* start with `/api/`).
    *   You **must** provide the correct **absolute path** to your frontend's build output directory (usually named `dist` or `pkg` depending on your build tool like `trunk` or `wasm-pack`). `cloudflared` needs read access to this directory.
4.  **SPA Routing (Deep Links):** `cloudflared`'s basic `file://` service will serve `index.html` when you request `/`. When your Wasm app loads, its internal router (like `yew-router`) takes over using the browser's History API. This usually works fine for navigation *within* the app. However, if a user directly navigates to `https://acounter.net/some/deep/link` or refreshes such a page, `cloudflared` might look for a file named `/some/deep/link` in your `dist` directory, not find it, and return a 404. More advanced setups might need a tiny intermediary server or different proxy logic to *always* serve `index.html` for non-asset, non-API paths, but start with this simple config first.
5.  **Axum Port:** Ensure your Axum app is indeed running on `127.0.0.1:3000` and using HTTPS (as specified by `service: https://...`). If Axum runs on HTTP, change the service to `http://127.0.0.1:3000` and remove `noTLSVerify`.
6.  **Restart `cloudflared`:** After saving the `config.yml`, make sure to restart your `cloudflared` tunnel service for the changes to take effect. Check the `cloudflared` logs (especially if using `loglevel: debug`) if things aren't working as expected.

This configuration provides a robust way to serve both parts of your application from the same domain using Cloudflare Tunnels. Remember to replace the placeholder paths with your actual configuration details.