// yara-rules.yar — Rules focused on credential theft & data exfiltration

rule CredentialHarvesting {
  meta:
    description = "Reads browser credential stores, OS keychains, or developer credential files"
  strings:
    $a = "chrome.cookies" nocase
    $b = ".git-credentials" nocase
    $c = ".claude/.credentials.json" nocase
    $d = "Chrome Safe Storage" nocase
    $e = "dump-keychain" nocase
    $f = "keytar.findCredentials" nocase
    $g = "key4.db" nocase
    $h = /["'\/\\]logins\.json/ nocase
    $chrome_login = /["'\/\\]Login Data["']/
    $chrome_state = /["'\/\\]Local State["']/
    $chrome_key = "encrypted_key"
    $cookie_exfil1 = /(fetch|XMLHttpRequest|sendBeacon|Image\(\)\.src)[^\n]{0,200}document\.cookie/
    $cookie_exfil2 = /document\.cookie[^\n]{0,200}(fetch\s*\(|XMLHttpRequest|sendBeacon|Image\(\)\.src)/
    $netrc = /["'\/~]\.netrc\b/
    $keytar_get = "keytar.getPassword"
  condition:
    any of ($a,$b,$c,$d,$e,$f,$g,$h,$chrome_login,$cookie_exfil1,$cookie_exfil2,$netrc,$keytar_get) or ($chrome_state and $chrome_key)
}

rule SensitiveFileAccess {
  meta:
    description = "Accesses SSH private keys, AWS credentials, or system password hashes"
  strings:
    // Private keys only (id_*.pub public keys are not secrets), and only when
    // read from the home dir: test data / config strings naming the path are not
    $a = /(open|readFile(Sync)?|read_text|read_bytes|createReadStream|expanduser|homedir\(\)|Path\.home\(\)|\$HOME|~|cat\s)[^\n]{0,80}\.ssh\/id_(rsa|ed25519|ecdsa|dsa)([^.a-zA-Z0-9_]|$)/
    $c = ".aws/credentials" nocase
    $e = /[^.]\/etc\/shadow/
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
    $c = /(^|[^a-zA-Z0-9.\-])t\.me\//
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
    $exec_dl1 = /(exec|spawn|system|popen|subprocess|Command::new)[^;\n]{0,120}curl.{0,60}\|\s*(ba)?sh/ nocase
    $exec_dl2 = /(exec|spawn|system|popen|subprocess|Command::new)[^;\n]{0,120}wget.{0,60}\|\s*(ba)?sh/ nocase
    // Shell scripts: the download must start a command (line start, ; or &&), not a comment or echo hint
    $sh_dl1 = /#!\/(usr\/)?bin\/(env[ \t]+)?(ba)?sh[^\x00]{0,1000}(\n|;|&&)[ \t]*(sudo[ \t]+)?curl[^\n]{0,60}\|[ \t]*(sudo[ \t]+)?(ba)?sh/ nocase
    $sh_dl2 = /#!\/(usr\/)?bin\/(env[ \t]+)?(ba)?sh[^\x00]{0,1000}(\n|;|&&)[ \t]*(sudo[ \t]+)?wget[^\n]{0,60}\|[ \t]*(sudo[ \t]+)?(ba)?sh/ nocase
  condition:
    any of them
}

rule RuntimeObfuscation {
  meta:
    description = "Decodes and executes an obfuscated payload in a single expression"
  strings:
    $chain = /(^|[^a-zA-Z0-9_.])(eval|exec|Function)\s*\([^\n]{0,80}(b64decode|b32decode|b85decode|a85decode|fromhex|atob|fromCharCode|Buffer\.from|zlib\.decompress|marshal\.loads|codecs\.decode)/
    $eval1 = "eval(Buffer.from" nocase
    $eval2 = "eval(atob(" nocase
    $eval3 = "exec(base64" nocase
    $eval4 = /eval\s*\(\s*fetch/ nocase
  condition:
    any of them
}

rule RuntimeObfuscationSplit {
  meta:
    description = "Decodes a payload and passes it to exec/eval within 400 bytes (lower confidence)"
  strings:
    $split = /(b64decode|b32decode|b85decode|a85decode|fromhex|atob|fromCharCode|zlib\.decompress|marshal\.loads)\s*\([\s\S]{0,400}[^a-zA-Z0-9_.](exec|eval|Function)\s*\(/
  condition:
    $split
}

rule SupplyChainHook {
  meta:
    description = "npm lifecycle script whose command performs remote or inline code execution"
  strings:
    $hook = /"(preinstall|install|postinstall|prepare)"\s*:\s*"[^"]{0,300}(curl|wget|node -e|python -c|bash -c|sh -c|eval\(|exec\()/
  condition:
    $hook
}
