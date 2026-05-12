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
    $d = "/etc/passwd"
    $e = "/etc/shadow"
    $f = ".gnupg/secring" nocase
    $g = ".gnupg/private-keys" nocase
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
    description = "Decodes and executes obfuscated payloads at runtime — requires 2+ indicators"
  strings:
    $a = "fromCharCode" nocase
    $b = /Buffer\.from\([^)]+,\s*['"]base64['"]\)/ nocase
    $c = "base64.b64decode" nocase
    $d = /\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}/
    $exec1 = "eval(" nocase
    $exec2 = "exec(" nocase
    $exec3 = "Function(" nocase
    $exec4 = "subprocess" nocase
  condition:
    // Must have at least one obfuscation indicator AND one execution indicator
    (any of ($a,$b,$c,$d)) and (any of ($exec1,$exec2,$exec3,$exec4))
}

rule SupplyChainHook {
  meta:
    description = "Suspicious npm lifecycle scripts that also contain remote execution"
  strings:
    $hook1 = "\"postinstall\"" nocase
    $hook2 = "\"preinstall\"" nocase
    $hook3 = "\"prepare\"" nocase
    $exec1 = /curl.{0,100}https?:\/\// nocase
    $exec2 = /wget.{0,100}https?:\/\// nocase
    $exec3 = "node -e" nocase
    $exec4 = "python -c" nocase
    $exec5 = "bash -c" nocase
    $exec6 = "sh -c" nocase
    $exec7 = "exec(" nocase
    $exec8 = "eval(" nocase
  condition:
    any of ($hook1,$hook2,$hook3) and any of ($exec1,$exec2,$exec3,$exec4,$exec5,$exec6,$exec7,$exec8)
}
