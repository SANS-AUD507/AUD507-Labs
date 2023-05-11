# Short Prompt:
function prompt{"PS > "}

# Get-history:
function gh {(Get-History).CommandLine}

# Copy last command in fenced code block:
function lb {"```````n" + ((Get-History).CommandLine | Select-Object -Last 1) + "`n```````n" | clip.exe}

# Copy last command:
function l {(Get-History).CommandLine | Select-Object -Last 1 | clip.exe}

# Set-location as code block 
function loc { ("```````nSet-Location " + (Get-Location).Path) + "`n``````"| clip.exe }

# To set prompt back to default:
<#
function prompt { "PS $($executionContext.SessionState.Path.CurrentLocation)$('>' * ($nestedPromptLevel + 1)) ";}
#>