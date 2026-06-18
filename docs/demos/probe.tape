# apisniff probe demo — defense preflight across four retail sites.
#
# Regenerate (from repo root, with a fresh binary on PATH):
#   go build -o apisniff ./cmd/apisniff
#   PATH="$PWD:$PATH" vhs docs/demos/probe.tape
#
# VHS renders its own synthetic terminal, so nothing from the real machine
# (home path, shell history, env) appears — the prompt is whatever we set below.

Output docs/demos/probe.gif

Set Shell "zsh"
Set FontSize 16
Set Width 1080
Set Height 460
Set Padding 24
Set Theme "Catppuccin Mocha"
Set TypingSpeed 55ms

# Clean, synthetic prompt — hidden from the recording.
Hide
Type "PROMPT='$ ' && RPROMPT='' && clear"
Enter
Show

Sleep 600ms

Type "apisniff probe costco.com"
Sleep 500ms
Enter
Sleep 3s

Type "clear"
Enter
Sleep 300ms

Type "apisniff probe target.com"
Sleep 500ms
Enter
Sleep 3s

Type "clear"
Enter
Sleep 300ms

Type "apisniff probe walmart.com"
Sleep 500ms
Enter
Sleep 4s
