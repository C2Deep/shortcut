__*shortcut*__ program is to manage the shortcuts (list, add, edit and remove). 

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
    sudo ./shortcut
```
```
    sudo ./shortcut-monitor
```

> [!IMPORTANT]
Both programs (__*shortcut*__ and __*shortcut-monitor*__) __must__ run with __sudo__ privileges to work.

> [!NOTE]
Although the shortcut-monitor program run with __sudo__ privileges, it does run the task associated with the shortcut as __normal user__.
