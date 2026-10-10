# Setup guide

From nothing to a working relay. Examples use the relay name `relay.example.com`, the server address
`10.0.0.25`, the domain `example.com` and the sender mailbox `notifications@example.com`; replace them with
your own. For how the code works, see [architecture.md](architecture.md).

| Step | What | Where |
|---|---|---|
| 1 | Server and DNS name | your network |
| 2 | App registration, client secret | Microsoft Entra admin center |
| 3 | Mail permissions limited to the relay mailboxes | Exchange Online |
| 4 | Portal admin role | Microsoft Entra admin center |
| 5 | API token for the certificate | Cloudflare |
| 6 | Install, configure, start | server |
| 7 | First sign-in, mailboxes, host rules, test | portal |
| 8 | Optional SMTP login per host | portal + device |
| 9–11 | Break-glass login, maintenance, troubleshooting | |

You need: Application Administrator (or Global Administrator) in Entra ID, Exchange Administrator, access to
the Cloudflare zone of your domain, and root on a Linux server. Plan about an hour, plus up to 2 hours for
Exchange permission changes to take effect.

---

## 1. Server and DNS name

- A Linux server or container (the deploy scripts target **Debian 12/13** with systemd and nftables) with
  outbound HTTPS to `login.microsoftonline.com`, `graph.microsoft.com`, `api.cloudflare.com` and Let's
  Encrypt. No inbound access from the internet is needed.
- A DNS name for the relay, e.g. `relay.example.com` → `10.0.0.25`. Clients and admins use it. For a private
  address, prefer an internal DNS record; if you put it into public DNS at Cloudflare, use **DNS only**
  (grey cloud), never proxied.
- The domain's DNS zone must be hosted at **Cloudflare**, which is how the TLS certificate is obtained (DNS-01).
  The relay name itself does not need to be public.

Optional: harden a fresh Debian host (updates, automatic security updates, key-only SSH, default-drop
firewall). Read [`deploy/harden-host.sh`](../deploy/harden-host.sh) first; adjust `TRUSTED_V4` (networks
allowed to reach SSH and the portal), then run it from your workstation:

```bash
ssh root@relay.example.com 'bash -s' < deploy/harden-host.sh
```

The firewall step rolls itself back after 120 seconds. Within that time, confirm from a **new** SSH session
that you can still log in:

```bash
ssh root@relay.example.com systemctl stop nft-rollback.timer
```

## 2. App registration and client secret (Entra ID)

1. Open <https://entra.microsoft.com> → **Entra ID → App registrations → + New registration**.
2. Fill in:
   - **Name:** e.g. `Graph Relay`
   - **Supported account types:** *Accounts in this organizational directory only (Single tenant)*
   - **Redirect URI:** platform **Web**, `https://relay.example.com:8443/auth/callback`
3. Click **Register**. On the **Overview** page note:
   - **Application (client) ID** → `GRAPH_CLIENT_ID`
   - **Directory (tenant) ID** → `GRAPH_TENANT_ID` (the GUID, not the domain name)
4. **Certificates & secrets → Client secrets → + New client secret**. Pick an expiry (max. 24 months), click
   **Add**, and **immediately copy the `Value` column** → `GRAPH_CLIENT_SECRET`. It is shown only once. Do not
   copy the *Secret ID*: that is a GUID and gives `AADSTS7000215: Invalid client secret`.
5. Put a reminder before the secret expires (see section 10).

**Do not add `Mail.Send` or `Mail.ReadWrite` under API permissions.** Granted there, with admin consent, the
app could send as and read **every mailbox in the tenant**, and that grant also bypasses the Exchange scope in
step 3 (the two are additive). If they were added already: on the **API permissions** page click **⋯** on each
row → **Revoke admin consent**, then **⋯** → **Remove permission**. Only the delegated `User.Read` should
remain. Check under **Enterprise applications → (app) → Permissions → Admin consent** that no `Mail.*`
application permission is left.

## 3. Mail permissions limited to the relay mailboxes (Exchange Online)

The relay sends through Graph as specific mailboxes. It needs **Mail.Send**, plus **Mail.ReadWrite** for
messages over ~3 MB (sent as drafts with attachments). Exchange **RBAC for Applications** grants them for a
defined set of mailboxes only.

The sender mailboxes can be user mailboxes or **shared mailboxes** (no licence needed), e.g.
`notifications@example.com`, `scanner@example.com`.

### 3a. Tag the mailboxes

Set **custom attribute 15** to `GraphRelay` on every mailbox the relay may send as. Either:

- **Exchange admin center** (<https://admin.exchange.microsoft.com>): **Recipients → Mailboxes** → click the
  mailbox → **Others** tab → **Custom attributes** → field **15** = `GraphRelay` → **Save**, or
- **PowerShell** (also needed for 3c):

```powershell
Install-Module ExchangeOnlineManagement -Scope CurrentUser    # once
Connect-ExchangeOnline -UserPrincipalName admin@example.com
Set-Mailbox notifications@example.com -CustomAttribute15 "GraphRelay"
```

If attribute 15 is already used in your tenant, pick another free one and change the filter in 3c.

### 3b. Find the service principal's Object ID

Exchange needs the Object ID of the **Enterprise application** (service principal). The portal shows three
similar GUIDs and only one is right:

| Where | Field | Use it? |
|---|---|---|
| App registration → Overview | Directory (tenant) ID | no, that's the tenant |
| App registration → Overview | Object ID | no, that's the app registration |
| Enterprise application → Properties | Object ID | **yes** |

The reliable way is to look it up from the client ID:

```powershell
Install-Module Microsoft.Graph.Applications -Scope CurrentUser    # once
Connect-MgGraph -Scopes Application.Read.All -NoWelcome
$appId    = "<Application (client) ID>"
$objectId = (Get-MgServicePrincipal -Filter "appId eq '$appId'").Id
$objectId   # must differ from both IDs on the App registration overview
```

If it comes back empty, the Enterprise application doesn't exist yet: create it with
`New-MgServicePrincipal -AppId $appId` (needs `Connect-MgGraph -Scopes Application.ReadWrite.All`).

### 3c. Create the scoped role assignments

In the same PowerShell window:

```powershell
New-ServicePrincipal -AppId $appId -ObjectId $objectId -DisplayName "Graph Relay"
Get-ServicePrincipal -Identity $appId | Format-List DisplayName,AppId,ObjectId    # check

New-ManagementScope -Name "Graph Relay mailboxes" `
  -RecipientRestrictionFilter "CustomAttribute15 -eq 'GraphRelay'"

New-ManagementRoleAssignment -App $appId -Role "Application Mail.Send" `
  -CustomResourceScope "Graph Relay mailboxes"
New-ManagementRoleAssignment -App $appId -Role "Application Mail.ReadWrite" `
  -CustomResourceScope "Graph Relay mailboxes"
```

### 3d. Verify

```powershell
Test-ServicePrincipalAuthorization -Identity $appId -Resource notifications@example.com   # InScope = True
Test-ServicePrincipalAuthorization -Identity $appId -Resource some.user@example.com       # InScope = False
Disconnect-ExchangeOnline -Confirm:$false; Disconnect-MgGraph
```

Changes take **30 minutes to 2 hours** to reach Graph; until then sends fail with `403 ErrorAccessDenied`.

### 3e. Message size (optional)

Exchange limits each mailbox to 35 MB per sent message by default (about 25 MB of attachments after encoding).
The relay accepts up to `smtp.max_message_bytes` (the example config uses 35 MB, the maximum is 150 MB). To
send larger mail, raise both:

```powershell
Set-Mailbox notifications@example.com -MaxSendSize 150MB
```

Internal recipients also have a `MaxReceiveSize` (default 36 MB); external servers apply their own limits.

## 4. Portal admin role (Entra ID)

Only users holding the app role **Relay.Admin** can sign in to the portal.

1. **Entra ID → App registrations →** your app **→ App roles → + Create app role**:
   - **Display name:** `Relay Admin`
   - **Allowed member types:** **Users/Groups** (with *Applications* only, it can't be assigned to people)
   - **Value:** `Relay.Admin` (exactly)
   - **Description:** `Can manage Graph Relay`; tick **Enable this app role** → **Apply**.
2. **Entra ID → Enterprise applications →** your app **→ Users and groups → + Add user/group** → select
   users or a group → role **Relay Admin** → **Assign**. Group assignment needs Entra ID P1, and roles are
   **not inherited through nested groups**: users must be direct members of the assigned group.
3. Recommended: **Enterprise applications →** your app **→ Properties → Assignment required? = Yes**.
4. Conditional Access and MFA policies apply to this sign-in like to any other app.

## 5. Cloudflare API token

1. <https://dash.cloudflare.com> → profile → **My Profile → API Tokens → Create Token** → template
   **Edit zone DNS** → **Use template**.
2. **Permissions:** `Zone · DNS · Edit` and (**+ Add more**) `Zone · Zone · Read`.
3. **Zone Resources:** `Include · Specific zone · example.com`.
4. Optional: **Client IP Address Filtering** with your server's public egress IP; an expiry date.
5. **Create Token** and copy it → `CLOUDFLARE_API_TOKEN` (shown only once). To check it:

```bash
curl -s -H "Authorization: Bearer <token>" https://api.cloudflare.com/client/v4/user/tokens/verify
```

## 6. Install, configure, start

### 6a. Configuration file

On your workstation, in the repository:

```bash
cp config.example.yaml config.yaml
```

Edit `config.yaml`:

| Setting | Value |
|---|---|
| `hostname` | `relay.example.com` |
| `data_dir` | `/opt/graphrelay/data` |
| `tls.acme_email` | an address for Let's Encrypt expiry notices |
| `tls.skip_dns_propagation_check` | `true` only if your network redirects all outbound DNS to an internal resolver (see section 11) |
| `tls.rsa_fallback` | `true` (default): also keep an RSA certificate for devices that can't use ECDSA |
| `smtp.max_message_bytes` | up to `157286400` (150 MB) |
| `portal.allowed_cidrs` | networks allowed to open the portal |
| `portal.microsoft_login.enabled` | `true`, `required_roles: ["Relay.Admin"]` |
| `portal.allow_local_login` | `${GRAPHRELAY_ALLOW_LOCAL_LOGIN}` (break-glass switch, section 9) |
| `firewall.allowlist_file` | `/opt/graphrelay/data/firewall-allowlist.txt` if you use the nftables integration |

Keep secrets out of the file: `graph.*` and `tls.cloudflare_api_token` already reference `${...}` variables.
`config.yaml` is ignored by git.

### 6b. Deploy

From the workstation (needs Go and SSH access as root):

```bash
CONFIG=config.yaml deploy/push.sh root@relay.example.com
```

This builds the Linux binary, copies it with all `deploy/` files and runs `install.sh` on the server, which
creates the `graphrelay` user and `/opt/graphrelay`, installs the systemd units and the firewall sync, and
copies the config only if the server has none yet. Without the push script, copy the binary, `config.yaml`
and the `deploy/` files into one directory on the server and run `bash install.sh` there.

### 6c. Secrets

```bash
ssh root@relay.example.com
nano /etc/graphrelay.env       # root:root, mode 0600
```

```
CLOUDFLARE_API_TOKEN=...
GRAPH_TENANT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
GRAPH_CLIENT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
GRAPH_CLIENT_SECRET=...
```

No spaces around `=`, no quotes.

### 6d. Start

```bash
systemctl start graphrelay
journalctl -u graphrelay -f
```

| Log line | Meaning |
|---|---|
| `created portal admin account ... password=...` | Local break-glass password, printed once (needed only if section 9 is ever used) |
| `certificate obtained successfully` | Cloudflare token and DNS-01 work (first start takes 1–2 minutes) |
| `SMTP listening` ×3, `management portal listening` | Relay is up |
| `Microsoft Graph authentication OK` | Tenant ID, client ID and secret are correct |
| `firewall allowlist updated ... entries=0` | No host rules yet, so the SMTP ports are still closed |

## 7. First sign-in, mailboxes, host rules, test

1. Open `https://relay.example.com:8443` and click **Sign in with Microsoft**.
2. **Settings → Allowed sender mailboxes:** enter the tagged mailboxes from 3a, one per line → **Save
   mailboxes**. Only these can be chosen for host rules and test messages; the relay also rejects mail for any
   rule whose mailbox is not on the list.
3. **Hosts → Add host:**
   - **Name:** e.g. `backup-server`
   - **Address / network:** an IP (`10.0.0.50`), a CIDR (`10.0.1.0/24`) or a DNS name
   - **Sends as mailbox:** choose from the list
   - **Rewrite the From header:** on (unless the mailbox has *Send As* rights for the device's own From address)
   - **Enabled:** on → **Save**
4. With the firewall integration, the SMTP ports open for that address within seconds:
   `nft list set inet filter smtp4`.
5. **Test:** choose the mailbox, send to yourself. A `403 ErrorAccessDenied` means the Exchange scope (step 3)
   is not active yet.
6. Point the device at `relay.example.com`, port 25 (or 587 with STARTTLS). Check **Log** for `sent` entries.

For each new sender mailbox: tag it (3a), add it under **Settings → Allowed sender mailboxes**, then pick it in
a host rule.

## 8. Optional SMTP login per host

In the host form, **SMTP login (optional)** takes a username and a password (**Generate** creates a random
one; copy it now, it is stored only as a hash). With a login set, a client must come from the rule's address
**and** log in; without a login it gets `530 Authentication required`. Leave both fields empty for devices
that can't authenticate.

Device settings: server `relay.example.com`, port **587 with STARTTLS** (or 25 with STARTTLS, or **465 with
SSL/TLS**), authentication on, mechanism PLAIN or LOGIN. AUTH is only offered over TLS.

**If the device doesn't trust the relay's certificate:** many printers and appliances ship without current
root certificates. Under **Settings → TLS certificates** download the **Root CA** (PEM, or DER/.cer for
devices that want a binary file) and import it into the device's trusted CA store. If it still refuses,
import the intermediate CA certificates too, or the CA bundle. Don't import the server certificate itself:
it is renewed about every 60 days. Five failed logins from
one IP lock it out for 15 minutes; failures appear in **Log**.

## 9. Break-glass password login

Normally only Microsoft sign-in is possible. If Entra ID sign-in breaks:

```bash
echo 'GRAPHRELAY_ALLOW_LOCAL_LOGIN=true' >> /etc/graphrelay.env
systemctl restart graphrelay
```

Sign in as `admin`. To set a new password (reads the env file, runs as the service user so the database keeps
its owner):

```bash
set -a; . /etc/graphrelay.env; set +a
cd /opt/graphrelay && setpriv --reuid=graphrelay --regid=graphrelay --init-groups \
  ./graphrelay -config config.yaml -reset-admin-password
```

Turn it off again:

```bash
sed -i '/^GRAPHRELAY_ALLOW_LOCAL_LOGIN=/d' /etc/graphrelay.env
systemctl restart graphrelay
```

## 10. Maintenance

| What | When | How |
|---|---|---|
| Client secret | Before it expires | New secret (step 2.4), update `/etc/graphrelay.env`, `systemctl restart graphrelay`, delete the old secret |
| Cloudflare token | If it has an expiry | New token (step 5), update the env file, restart |
| TLS certificate | Automatic | Renewed about 30 days before expiry |
| OS updates | Automatic | `unattended-upgrades` (set up by `harden-host.sh`) |
| Relay upgrade | When needed | `CONFIG=config.yaml deploy/push.sh root@relay.example.com`; config, env file and database are kept |
| Backup | Regularly | `/opt/graphrelay/data/` (database, certificates) and `/etc/graphrelay.env` restore everything |
| Message log | Automatic | Rows older than `log_retention_days` (default 30) are deleted |

## 11. Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `AADSTS7000215: Invalid client secret` | The Secret **ID** was used instead of the **Value**, or the secret expired |
| `AADSTS900021` / `AADSTS90002` | `GRAPH_TENANT_ID` is wrong; use the Directory (tenant) ID GUID |
| `AADSTS700016` application not found | `GRAPH_CLIENT_ID` is wrong or from another tenant |
| `New-ServicePrincipal`: `AADServicePrincipalNotFound` | Wrong Object ID: use the Enterprise application's (step 3b) |
| Test send: `403 ErrorAccessDenied` | Mailbox not tagged (3a), wrong scope, or the change hasn't propagated yet (up to 2 h). Check with `Test-ServicePrincipalAuthorization` |
| Test send: `404 ErrorInvalidUser` | The sender mailbox doesn't exist |
| Sign-in: `AADSTS50011` redirect URI mismatch | Fix the redirect URI (step 2.2); it must include `:8443` |
| Sign-in: `AADSTS50105` user not assigned | *Assignment required* is on and the user isn't assigned (step 4.2) |
| Portal: "... is not allowed to manage this relay" | No `Relay.Admin` role in the token: assign it, check nested groups, sign in again in a private window. The journal shows the roles found (`roles=[...]`) |
| Certificate: `timed out waiting for record to fully propagate` | The network redirects outbound DNS to an internal resolver that doesn't see the Cloudflare TXT record. Set `tls.skip_dns_propagation_check: true` |
| Certificate: Cloudflare `403` / `9109` | Token lacks `Zone:Read` or `DNS:Edit`, or isn't limited to the right zone |
| Device reports an SSL/TLS error although the CA is imported | The device may support only RSA cipher suites or only TLS 1.0/1.1. RSA-only devices need `tls.rsa_fallback: true` (the default); the relay requires TLS 1.2 or newer. `LOG_LEVEL=debug` shows handshake errors |
| Client: connection refused / timeout | No enabled host rule for its IP, so the firewall blocks it: `nft list set inet filter smtp4` and `journalctl -u graphrelay-fw.service` |
| Client gets `530 Authentication required` | The rule has an SMTP login; configure it on the device (section 8) |
| Client gets `554 ... Sender mailbox ... not allowed` | The rule's mailbox was removed from the allowed list |
| Client gets `451` | Temporary Graph error or throttling; the client retries by itself |
| Client gets `554` with a Graph error | Permanent refusal (e.g. size over the mailbox's `MaxSendSize`); details in **Log** |
