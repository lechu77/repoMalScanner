# Cómo verificar manualmente la exposición al ataque TanStack (TeamPCP, 11 mayo 2026)

## Qué pasó

El 11/05/2026 entre las 19:20 y 19:26 UTC, el grupo **TeamPCP** publicó 84 versiones maliciosas de 42 paquetes `@tanstack/*` en npm. El ataque encadenó tres vulnerabilidades de GitHub Actions para robar un token OIDC y publicar sin credenciales npm propias.

**El malware, al ejecutarse durante `npm install`:**
- Roba credenciales: AWS (IMDS/Secrets Manager), GCP, Kubernetes, Vault, GitHub tokens, SSH keys, `~/.npmrc`
- Exfiltra por tres canales: dominio typosquat `git-tanstack.com`, red Session (`*.getsession.org`), GitHub dead drops
- Instala un daemon persistente (`gh-token-monitor`) que ejecuta `rm -rf ~/` si detecta que revocaste el token de GitHub
- Se autopropaga: publica versiones infectadas de otros paquetes que la víctima mantiene en npm

También afectados: `@uipath/*`, `@mistralai/mistralai` (npm), `guardrails-ai` y `mistralai` (PyPI).

---

## Paso 1 — Verificar paquetes npm instalados

### Global

```bash
npm list -g --depth=0 | grep -E "@tanstack|@uipath|mistralai|wot-api|beproduct"
```

### En un proyecto específico

```bash
npm list --depth=0 | grep -E "@tanstack|@uipath|mistralai"
```

### Buscar en todo `$HOME` (node_modules anidados)

```bash
find ~ -maxdepth 8 -name "package.json" \
  -path "*/@tanstack/*" \
  -not -path "*/node_modules/@tanstack/*/node_modules/*" \
  2>/dev/null
```

Si encontrás algún resultado, verificá la versión instalada contra la lista de versiones afectadas en el [GitHub Security Advisory GHSA-g7cv-rxg3-hmpx](https://github.com/TanStack/router/security/advisories/GHSA-g7cv-rxg3-hmpx).

---

## Paso 2 — Verificar paquetes Python (pip / pipx)

```bash
pip list | grep -iE "guardrails|mistralai"
pipx list | grep -iE "guardrails|mistralai"
```

Versiones maliciosas: `guardrails-ai==0.10.1`, `mistralai==2.4.6`.

---

## Paso 3 — Buscar archivos IOC del malware

Estos archivos son artefactos que el malware deja en disco, incluso después de desinstalar el paquete:

```bash
find ~ -maxdepth 8 \( \
  -name "router_init.js" \
  -o -name "router_runtime.js" \
  -o -name "tanstack_runner.js" \
  -o -name "setup.mjs" -path "*/@tanstack/*" \
\) 2>/dev/null
```

También buscar en directorios de IDEs (persisten tras `npm uninstall`):

```bash
find ~/.claude ~/.vscode -name "router_runtime.js" -o -name "setup.mjs" 2>/dev/null
```

---

## Paso 4 — Verificar el daemon persistente (¡hacer ANTES de revocar tokens!)

> ⚠️ **Importante**: el daemon `gh-token-monitor` ejecuta `rm -rf ~/` si detecta que el token GitHub fue revocado. Eliminarlo **antes** de rotar credenciales.

### macOS

```bash
# Verificar si existe
ls ~/Library/LaunchAgents/ | grep gh-token-monitor

# Si existe, desactivarlo y eliminarlo
launchctl unload ~/Library/LaunchAgents/com.user.gh-token-monitor.plist
rm ~/Library/LaunchAgents/com.user.gh-token-monitor.plist
```

### Linux

```bash
# Verificar si existe
systemctl --user list-units | grep gh-token-monitor

# Si existe, desactivarlo y eliminarlo
systemctl --user stop gh-token-monitor
systemctl --user disable gh-token-monitor
rm ~/.config/systemd/user/gh-token-monitor.service
```

---

## Paso 5 — Verificar en lockfiles si instalaste versiones afectadas el 11/05

Si tenés `package-lock.json` o `pnpm-lock.yaml` en un proyecto, buscá referencias al commit malicioso:

```bash
grep -r "79ac49eedf774dd4b0cfa308722bc463cfe5885c" .
grep -r "git-tanstack" .
grep -r "@tanstack/setup" .
```

---

## Paso 6 — Rotar credenciales (si hubo exposición)

Si instalaste alguna versión afectada el **11/05/2026**, tratá el host como comprometido y rotá:

- GitHub tokens (PAT y OAuth)
- npm tokens
- AWS credentials (Access Key + Secret)
- GCP service account keys
- Kubernetes service account tokens
- HashiCorp Vault tokens
- SSH keys accesibles desde el host

---

## Indicadores de compromiso (IOCs)

| Tipo | Valor |
|---|---|
| Dependencia maliciosa | `"@tanstack/setup": "github:tanstack/router#79ac49eedf774dd4b0cfa308722bc463cfe5885c"` |
| Archivo en tarball | `router_init.js` (~2.3 MB, obfuscado) |
| C2 dominio | `git-tanstack.com` |
| C2 red | `filev2.getsession.org`, `seed1/2/3.getsession.org` |
| C2 IP | `83.142.209.194` |
| Daemon macOS | `~/Library/LaunchAgents/com.user.gh-token-monitor.plist` |
| Daemon Linux | `~/.config/systemd/user/gh-token-monitor.service` |
| Repo description (dead drop) | `Shai-Hulud: Here We Go Again` |

---

## Paquetes npm afectados (familias)

Las versiones maliciosas son las publicadas el 11/05/2026. Todas están deprecadas en npm.
Listado completo en [GHSA-g7cv-rxg3-hmpx](https://github.com/TanStack/router/security/advisories/GHSA-g7cv-rxg3-hmpx).

Familias comprometidas de `@tanstack/*`:
- `@tanstack/router`, `@tanstack/react-router`, `@tanstack/history`
- `@tanstack/start-*` (subpaquetes, no el meta-paquete `@tanstack/start`)
- **No afectados**: `@tanstack/query*`, `@tanstack/table*`, `@tanstack/form*`, `@tanstack/virtual*`, `@tanstack/store`

Otros namespaces: `@uipath/apollo-core`, `@uipath/cli`, `@uipath/agent-sdk` y variantes.

---

## Referencias

- [Postmortem oficial TanStack](https://tanstack.com/blog/npm-supply-chain-compromise-postmortem)
- [Análisis Wiz (TeamPCP / Mini Shai-Hulud)](https://www.wiz.io/blog/mini-shai-hulud-strikes-again-tanstack-more-npm-packages-compromised)
- [GitHub Security Advisory GHSA-g7cv-rxg3-hmpx](https://github.com/TanStack/router/security/advisories/GHSA-g7cv-rxg3-hmpx)
- [Socket.dev análisis](https://socket.dev/blog/tanstack-npm-packages-compromised-mini-shai-hulud-supply-chain-attack)
