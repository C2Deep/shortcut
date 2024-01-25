__*shortcut*__ program is to manage the shortcuts like
list, add, edit and remove. 

__*shortcut-monitor*__ program monitor the keyboard to detect the keys combination up to 10 keys at once (8 keys combination is the maximum on my machine) and execute the associated task.

__Compile and link__:
    gcc -o shortcut shortcut.c
    gcc -o shortcut-monitor shortcut-monitor.c

__Usage__:
> sudo ./shortcut path_to_keyboard_event_file

> sudo ./shortcut-monitor $USER path_to_keyboard_event_file

> [!TIP]
> path_to_keyboard_event_file or keyboard file handler could be found using some bash :
```
  echo "/dev/input/by-path/"$(ls/dev/input/by-path | grep kbd)
```
> tested on Kubuntu 22.04.3 LTS

> If the bash code didn't work for you then check [how to find keyboard event file](https://unix.stackexchange.com/questions/82064/how-to-get-the-actual-keyboard-device-given-the-output-of-proc-bus-input-device)

> [!IMPORTANT]
Both program MUST run with sudo privileges to work.

> [!NOTE]
Although the shortcut-monitor program run with sudo privileges, it does run the task associated with the shortcut as normal user.
