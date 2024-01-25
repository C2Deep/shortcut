Compile and link with:
gcc -o shortcut shortcut.c
gcc -o shortcut-monitor shortcut-monitor.c


shortcut program is to manage the shortcuts like
list, add, edit and remove. 

shortcut-monitor program monitor the keyboard to detect the keys combination and execute the associated task.

Both program MUST run with sudo privileges

NOTE: although the shortcut-monitor program run with sudo privileges, it does run the task associated with the shortcut as normal user.
