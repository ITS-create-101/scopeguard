# Record the scopeguard demo GIF with vhs (https://github.com/charmbracelet/vhs)
#   brew install vhs    # or: go install github.com/charmbracelet/vhs@latest
#   vhs demo.tape       # -> produces demo.gif
Output demo.gif
Set FontSize 24
Set Width 1200
Set Height 640
Set Theme "Dracula"
Set Padding 28
Type "python3 demo.py"
Sleep 600ms
Enter
Sleep 4s
