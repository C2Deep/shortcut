__*shortcut*__ program is to manage the shortcuts like
list, add, edit and remove shortcuts. 

__*shortcut-monitor*__ program monitor the keyboard to detect the keys combination from 2 up to 8 keys at once (8 keys combination is the maximum on my machine <ins>but</ins> you can change it within both programs source code and recompile) and execute the associated task.

__Enviroment__:
    Linux
    
__Compile and link__:
```
    gcc -o shortcut shortcut.c
```
```
    gcc -o shortcut-monitor shortcut-monitor.c
```
__Usage__:
```
    sudo ./shortcut path_to_keyboard_event_file
```
```
    sudo ./shortcut-monitor $USER path_to_keyboard_event_file
```

> [!TIP]
> path_to_keyboard_event_file or keyboard file handler could be found using shell commands :
```
  echo "/dev/input/by-path/"$(ls /dev/input/by-path | grep kbd)
```
> Tested on Kubuntu 22.04.3 LTS

> If the above shell snippet didn't work for you then check [how to find keyboard event file](https://unix.stackexchange.com/questions/82064/how-to-get-the-actual-keyboard-device-given-the-output-of-proc-bus-input-device)

> [!IMPORTANT]
Both programs (__*shortcut*__ and __*shortcut-monitor*__) __must__ run with __sudo__ privileges to work.

> [!NOTE]
Although the shortcut-monitor program run with __sudo__ privileges, it does run the task associated with the shortcut as __$USER__.
