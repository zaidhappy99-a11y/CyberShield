$base = "C:\Users\HP\OneDrive\Documents\CyberSecurity-Project"

$dirs = @(
  "src\reconnaissance",
  "src\scanning",
  "src\exploitation",
  "src\post_exploitation",
  "src\reporting",
  "src\utils",
  "tools\network",
  "tools\web",
  "tools\crypto",
  "tools\forensics",
  "scripts\automation",
  "scripts\setup",
  "docs\reports",
  "docs\writeups",
  "docs\methodology",
  "logs",
  "data\wordlists",
  "data\payloads",
  "data\signatures",
  "tests",
  "configs"
)

foreach ($dir in $dirs) {
  New-Item -ItemType Directory -Path "$base\$dir" -Force | Out-Null
}

Write-Host "All directories created successfully."
