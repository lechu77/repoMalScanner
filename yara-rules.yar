// yara-rules.yar — Rules focused on credential theft & data exfiltration

rule CredentialHarvesting {
  meta:
    description = "Reads browser cookies, localStorage, or OS credential stores"
  strings:
    $a = "document.cookie" nocase
    $b = "chrome.cookies" nocase
    $c = "SecItemCopyMatching" nocase
    $d = "credentials.json" nocase
    $e = ".git-credentials" nocase
    $f = "netrc" nocase
    $g = "localStorage.getItem" nocase
    $h = "sessionStorage.getItem" nocase
    $i = "keytar.getPassword" nocase
  condition:
    any of them
}

rule SensitiveFileAccess {
  meta:
    description = "Accesses SSH keys, AWS credentials, or system password files"
  strings:
    $a = ".ssh/id_rsa" nocase
    $b = ".ssh/id_ed25519" nocase
    $c = ".aws/credentials" nocase
    $d = ".aws/config" nocase
    $e = "/etc/passwd"
    $f = "/etc/shadow"
    $g = ".gnupg" nocase
    $h = "~/.config" nocase
  condition:
    any of them
}

rule DataExfiltration {
  meta:
    description = "Sends data to external endpoints (webhook, pastebin, discord, telegram)"
  strings:
    $a = "webhook.site" nocase
    $b = "discord.com/api/webhooks" nocase
    $c = "t.me/" nocase
    $d = "api.telegram.org" nocase
    $e = "pastebin.com" nocase
    $f = "requestbin" nocase
    $g = "ngrok.io" nocase
    $h = "burpcollaborator" nocase
    $i = "pipedream.net" nocase
  condition:
    any of them
}

rule RemoteCodeExecution {
  meta:
    description = "Downloads and executes remote code"
  strings:
    $a = /curl.{0,50}\|\s*(ba)?sh/ nocase
    $b = /wget.{0,50}\|\s*(ba)?sh/ nocase
    $c = "eval(Buffer.from" nocase
    $d = "eval(atob(" nocase
    $e = "exec(base64" nocase
  condition:
    any of them
}

rule RuntimeObfuscation {
  meta:
    description = "Decodes and executes obfuscated payloads at runtime"
  strings:
    $a = "fromCharCode" nocase
    $b = /Buffer\.from\([^)]+,\s*['"]base64['"]\)/ nocase
    $c = "base64.b64decode" nocase
    $d = /\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}/
  condition:
    any of them
}

rule SupplyChainHook {
  meta:
    description = "Suspicious npm lifecycle scripts (postinstall/preinstall)"
  strings:
    $a = "\"postinstall\"" nocase
    $b = "\"preinstall\"" nocase
    $c = "\"prepare\"" nocase
  condition:
    any of ($a, $b, $c)
}
