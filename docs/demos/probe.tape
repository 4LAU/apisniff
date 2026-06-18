# apisniff probe demo — defense preflight across three retail sites.
#
# Replays pre-captured output (docs/demos/captures/*.ansi via the demo-bin shim),
# so output is instant: every panel gets the exact same read time and the live
# sites are never re-hit on render. Regenerate captures with capture.py.
#
# Render (from repo root):
#   PATH="$PWD/docs/demos/demo-bin:$PATH" vhs docs/demos/probe.tape
#
# VHS renders its own synthetic terminal — nothing from the real machine
# (home path, shell history, env) appears; the prompt is whatever we set below.

Output docs/demos/probe.gif

Set Shell "zsh"
Set FontSize 20
Set Width 1200
Set Height 720
Set Padding 24
Set Margin 28
Set MarginFill "#3B4FE3"
Set WindowBar Colorful
Set BorderRadius 12
Set Theme "Catppuccin Mocha"
Set TypingSpeed 55ms
Set Framerate 24

# Clean, synthetic prompt — hidden from the recording.
Hide
Type "PROMPT='$ ' && RPROMPT='' && clear"
Enter
Show

Sleep 800ms

Type "apisniff probe costco.com"
Sleep 400ms
Enter
Sleep 4s

Type "clear"
Enter
Sleep 400ms

Type "apisniff probe target.com"
Sleep 400ms
Enter
Sleep 4s

Type "clear"
Enter
Sleep 400ms

Type "apisniff probe walmart.com"
Sleep 400ms
Enter
Sleep 4s

Type "clear"
Enter
Sleep 400ms
