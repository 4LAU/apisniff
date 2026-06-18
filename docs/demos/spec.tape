# apisniff spec + share demo — capture to OpenAPI, then export safely.
#
# Replays pre-captured output (docs/demos/captures/spec-pokeapi.co.ansi and
# share-pokeapi.co.ansi via the demo-bin shim) from a PokeAPI capture bundle.
# spec/share read a local bundle (no network); replay keeps the GIF deterministic
# and avoids committing the raw bundle. Regenerate captures with capture.py.
#
# Render (from repo root):
#   PATH="$PWD/docs/demos/demo-bin:$PATH" vhs docs/demos/spec.tape

Output docs/demos/spec.gif

Set Shell "zsh"
Set FontSize 20
Set Width 1200
Set Height 440
Set Padding 24
Set Margin 28
Set MarginFill "#3B4FE3"
Set WindowBar Colorful
Set BorderRadius 12
Set Theme "Catppuccin Mocha"
Set TypingSpeed 55ms
Set Framerate 24

Hide
Type "PROMPT='$ ' && RPROMPT='' && clear"
Enter
Show

Sleep 800ms

Type "apisniff spec pokeapi.co"
Sleep 400ms
Enter
Sleep 4s

Type "clear"
Enter
Sleep 400ms

Type "apisniff share pokeapi.co -o pokeapi-export"
Sleep 400ms
Enter
Sleep 4s

Type "clear"
Enter
Sleep 400ms
