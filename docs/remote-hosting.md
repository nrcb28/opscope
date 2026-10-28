# Run Opscope on a remote server

Opscope can run on a Linux VM in any cloud. Its collector describes that VM; cloud adapters additionally query the explicitly selected provider accounts. Hosting Opscope in Azure does not automatically connect AWS, GCP or an Azure subscription. Configure the provider identity and read scope on the host that runs Opscope.

The examples below are deployment templates. No server, DNS record, certificate, cloud identity or public service is created by the repository. Replace the example domain and choose the accounts and read scopes you are authorized to inspect.

## Private access through SSH

Start the downloaded binary on the server with a fixed loopback port:

```sh
./opscope serve --port 48321
```

On your computer open an SSH tunnel, then use the local bootstrap URL printed by the server:

```sh
ssh -N -L 127.0.0.1:48321:127.0.0.1:48321 user@server
```

Keep the `#token=...` fragment private. The browser removes it after opening the local session. The default listener remains `127.0.0.1`; do not expose port 48321 through a firewall or load balancer.

## HTTPS access through an authenticated proxy

For browser access at a public HTTPS domain, use a same-host reverse proxy. The included [Caddyfile](../deploy/remote/Caddyfile) requires Caddy 2.8 or later, obtains TLS certificates, and requires HTTP Basic authentication before serving any page or API route. Caddy replaces any client-supplied `X-Opscope-Token` with a separate 256-bit upstream secret and strips the browser's `Authorization` and `Cookie` headers before forwarding to Opscope.

Basic authentication is one operator-managed entry point for this shared, read-only workspace. It does not create Opscope users, per-user cloud identities or cloud accounts. An existing OIDC gateway can replace it if that gateway protects every route, including assets, downloads and SSE, and performs the same header replacement. Do not remove authentication from the example proxy.

Opscope always listens on loopback. Its explicit proxy mode validates the configured public Host, Origin, referrer and Fetch Metadata, checks the upstream secret, and ignores forwarded identity/origin headers. The public bootstrap URL contains no token. The browser discovers proxy mode only through the protected `/api/session` endpoint and uses same-origin requests; it never receives or stores the upstream secret.

1. Point a domain such as `opscope.example.com` at the VM. Allow inbound HTTPS and the HTTP access needed by Caddy's chosen ACME challenge, plus your administrative access. Keep 48321 private. Install the appropriate verified Opscope archive under `/opt/opscope/` and install Caddy from its official distribution.
2. Create a dedicated unprivileged service account whose home is `/var/lib/opscope`. For example, on a distribution with `useradd`:

   ```sh
   sudo useradd --system --user-group --home-dir /var/lib/opscope --shell /usr/sbin/nologin opscope
   sudo install -d -m 0700 -o opscope -g opscope /var/lib/opscope
   sudo install -d -m 0700 /etc/opscope
   ```

3. Generate a random 64-hex-character secret with `openssl rand -hex 32` through your approved secret provisioning workflow. Put the **same value** in the two root-readable files below. Keep it out of arguments, URLs, shell history, reports and support messages. Generate a separate password hash using `caddy hash-password` and choose a strong browser login password. Use a protected editor or your secret manager to create the files with mode 0600; do not paste the placeholders literally:

   `/etc/opscope/opscope.env`:

   ```text
   OPSCOPE_PUBLIC_ORIGIN=https://opscope.example.com
   OPSCOPE_PROXY_TOKEN=<64-hex-random-secret>
   ```

   `/etc/opscope/proxy.env`:

   ```text
   OPSCOPE_PUBLIC_HOST=opscope.example.com
   OPSCOPE_USER=<operator-login-name>
   OPSCOPE_PASSWORD_HASH=<caddy-password-hash>
   OPSCOPE_PROXY_TOKEN=<same-64-hex-random-secret>
   ```

   Systemd environment files preserve dollar signs in the hash; do not source these files in a shell. The public origin is an HTTPS origin only: no user information, path other than `/`, query or fragment. Host and optional nondefault port must match the public proxy exactly. The upstream secret must contain exactly 64 hexadecimal characters. Opscope rejects incomplete or invalid proxy configuration before collection or history initialization.

4. Install [opscope.service](../deploy/remote/opscope.service) as `/etc/systemd/system/opscope.service`. Install the example Caddyfile at `/etc/caddy/Caddyfile` and [caddy-opscope.conf](../deploy/remote/caddy-opscope.conf) as `/etc/systemd/system/caddy.service.d/opscope.conf`, creating that directory first. Keep the service files root-owned. Validate the Caddy configuration using the protected service environment through your deployment tooling, then reload systemd and restart both services:

   ```sh
   sudo systemctl daemon-reload
   sudo systemctl enable --now opscope
   sudo systemctl restart caddy
   ```

5. Open `https://opscope.example.com/`, complete the proxy login, and open **Connections**. The server prints the public URL without a secret fragment. Confirm unauthenticated access is challenged by Caddy and port 48321 is unreachable externally. Check the configured read action and its coverage before drawing conclusions from provider results.

The equivalent Opscope invocation is:

```sh
opscope serve --port 48321 --public-origin https://opscope.example.com --proxy-token-env OPSCOPE_PROXY_TOKEN
```

Only the environment variable name appears in the command. For secret rotation update both protected files to the same new random value and restart Opscope and Caddy. Rotate the browser password separately when needed. Do not run a reverse proxy on a separate host: this mode requires a loopback upstream peer on the same server.

## Connect the service to provider accounts

The Connections menu provides fixed official registration, console and documentation links, credential presence checks, trusted CLI readiness, operation requirements and a test of an already configured read action. These checks do not authenticate an account or grant permissions. Registration and login happen through the provider's official tools; the app does not collect console passwords, upload kubeconfig files or create cloud infrastructure.

Configure CLI sessions, ADC, API tokens or workload identities for the **service account**, and add the intended `--cloud` and scope arguments to `ExecStart`. A login performed as your SSH user does not configure the `opscope` service. The supplied service uses `ProtectHome=true`, which hides ordinary `/home` profiles; keep service configuration under `/var/lib/opscope` or use approved provider-specific config selectors there. Its dedicated account's home is `/var/lib/opscope`. For an interactive CLI setup, an administrator can invoke the official CLI as that account with `sudo -u opscope -H <provider-cli> ...`, following the Connections guide. Keep credentials and identity files private to that account. For GCP, a `gcloud` session and Application Default Credentials are separate requirements.

For example, after provisioning an existing AWS read profile, append `--cloud aws --profile <profile> --region <region>` to the service command, then reload and restart it. API-token providers use their named environment variables in the protected Opscope environment file. Cloud provider credentials belong in `opscope.env` or the service's protected provider configuration, **not** in `proxy.env`, the Caddyfile, browser storage or URLs. Configure least-privilege read access for the selected operations as described in [cloud.md](cloud.md).

Provider permission denial, missing setup and quota limits have different diagnostics. A provider denial does not end the Opscope session. A successful read proves only that action's access at its observation time. Partial evidence preserves available observations; unavailable or unrequested sources do not imply a healthy or empty cloud account.

The service's persistent history is under `/var/lib/opscope`, mode 0700, with the app's redaction and retention limits. Back up or delete that directory according to your retention policy. Run one workspace per intended set of cloud scopes; everyone admitted by the proxy can read the workspace's configured evidence and invoke its allowlisted reads, including the explicit full-identifier snapshot view. Use separate service/proxy instances when different audiences require different access.
