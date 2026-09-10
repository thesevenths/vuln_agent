# Clone or update RuoJi6/java-audit-skills into vendor/
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$Target = Join-Path $Root "vendor\java-audit-skills"
$Repo = "https://github.com/RuoJi6/java-audit-skills.git"

if (Test-Path (Join-Path $Target ".git")) {
    Write-Host "Updating $Target ..."
    git -C $Target pull --ff-only
} else {
    New-Item -ItemType Directory -Force -Path (Split-Path $Target) | Out-Null
    Write-Host "Cloning $Repo -> $Target ..."
    git clone --depth 1 $Repo $Target
}

$skillMd = Join-Path $Target "skills\java-route-mapper\SKILL.md"
if (-not (Test-Path $skillMd)) {
    Write-Error "Clone incomplete: missing $skillMd"
}
Write-Host "OK: java-audit-skills ready at $Target"
Write-Host "Set JAVA_AUDIT_SKILLS_PATH=$Target in .env"
