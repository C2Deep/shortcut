// Detect shortcut keys combination and execute the associated task

#include<stdio.h>                      // input/output functions
#include<stdbool.h>                    // true, false
#include<string.h>                     // string functions (str***())
#include<stdlib.h>                     // malloc(), realloc(), system()
#include <fcntl.h>                     // open()
#include<unistd.h>                     // read(), write(), getlogin()
#include<linux/input.h>                // for struct input_event
#include<string.h>                     // strlen(), strstr()
#include<ctype.h>                      // toupper()

#define TASK_SIZE      256           // Maximum number of characters for a task array
#define MAX_KEYSCOMBO  8             // Maximum number of keys pressed in combination at once


struct Keys
{
    unsigned char kCodes[MAX_KEYSCOMBO];          // Array of binary representation of the key
    unsigned char kSize;                          // Size of the array
    bool kComboFlag;                              // Keys combination  flag
};

char *search_combo(struct Keys *KeyCodes);
void keys_combo(struct input_event *pEvent, struct Keys *KeysCodes);
void *realloc_mem(void* mem,size_t size, const char* varName);
int find_event_num(char* deviceName);
char *find_device(char *deviceName);

int main(int argc, char *argv[])
{
    struct Keys *KeysInfo = malloc(sizeof(struct Keys));
    const char CHUNCK = sizeof(struct input_event);
    struct input_event *pEvent = NULL;
    char **pKeys = NULL;
    char *exeTask = NULL;
    char *unSudoTask = NULL;
    char *userName = NULL;
    char *devicePath = NULL;
    int KBfd = -1;
    unsigned char length = 0,
                  len   = 0;

    userName = getlogin();
    if(!userName)
    {
        fprintf(stderr, "Couldn't get the username.\n");
        return -1;
    }

    len = strlen(userName) + 9;  // +9 "sudo -u" and '\0';

    devicePath = find_device("keyboard");
    if((KBfd = open(devicePath, O_RDONLY)) == -1)
    {
        fprintf(stderr, "Couldn't open Keyboard event file for reading.\n");
        printf("Usage: sudo %s\n", argv[0]);
        free(devicePath);
        return -1;
    }

    free(devicePath);

    if(!(unSudoTask = malloc(1)))
    {
        fprintf(stderr, "Couldn't allocate memory for unSudoTask.\n");
        return -1;
    }

    if(!(pEvent = malloc(sizeof(CHUNCK))))
    {
        fprintf(stderr, "Couldn't allocate memory for pEvent.\n");
        return -1;
    }

    for(;;)
    {
        read(KBfd, pEvent, CHUNCK);
        keys_combo(pEvent, KeysInfo);

        if(KeysInfo->kComboFlag)
            if((exeTask = search_combo(KeysInfo)))
            {
                printf("\e[1;1H\e[2J"); // clear the screen
                printf("Executing: %s.\n", exeTask);
                length = strnlen(exeTask, TASK_SIZE);
                unSudoTask =  realloc_mem(unSudoTask, length + len, "unSudoTask");
                sprintf(unSudoTask, "sudo -u %s %s",userName, exeTask);  // turn off sudo
                system(unSudoTask);

            }
    }
    free(exeTask);
    return 0;
}


// return the keys combination in array in binary form
void keys_combo(struct input_event *pEvent, struct Keys *KeysCodes)
{

    static unsigned char counter = 0;
    static unsigned char lastCode = 0xff;   // just big number to not interfere with the codes in array
    static bool keyCombo = false;
    static bool comboBreak = true;      // Break the rest of the keys to printed after the first key relasesd

    if(pEvent->type == 1)
        switch(pEvent->value)
        {
            case 0:
                KeysCodes->kSize = counter;

                if(counter < 2 || !comboBreak)
                   KeysCodes->kComboFlag = false;

                else
                    KeysCodes->kComboFlag = true;

                lastCode = pEvent->code;
                comboBreak = false;
                counter = 0;
                break;
            case 1:
                KeysCodes->kCodes[counter++] = pEvent->code;
                KeysCodes->kSize = counter;
                KeysCodes->kComboFlag = false;
                comboBreak = true;
                break;
        }
    else
        KeysCodes->kComboFlag = false;
}

char *search_combo(struct Keys *KeyCodes)
{
    FILE *pKeysTasksFile = fopen("KEYSTASKS.sc", "r");
    if(!pKeysTasksFile)
    {
        pKeysTasksFile = fopen("KEYSTASKS.sc", "w");    // create it
        fclose(pKeysTasksFile);

        if(!pKeysTasksFile)
        {
            fprintf(stderr, "Couldn't create KEYSTASKS.sc file.\n");
            exit(-1);
        }

        pKeysTasksFile = fopen("KEYSTASKS.sc", "r");
        if(!pKeysTasksFile)
        {
            fprintf(stderr, "Couldn't open KEYSTASKS.sc for reading.\n");
            exit(-1);
        }

    }

    char codesBuf[MAX_KEYSCOMBO];
    char *taskBuf = NULL;
    char task[TASK_SIZE];
    unsigned char length = 0;
    bool bingo = false;

    for(; !feof(pKeysTasksFile) ;)
    {
        fread(&length, sizeof(char), 1, pKeysTasksFile);
        if(length == KeyCodes->kSize)
        {
            fread(codesBuf, sizeof(char), length, pKeysTasksFile);
            if(!(strncmp(codesBuf, KeyCodes->kCodes, length)))
                bingo = true;   // Bingo !! .. found it
        }
        else
            fread(codesBuf, sizeof(char), length, pKeysTasksFile);

        fread(&length, sizeof(char), 1, pKeysTasksFile);    // reading the length of task


        if(bingo)
        {
            if(!(taskBuf = malloc(length + 1) ))                  // +1 for '\0'
            {
                fprintf(stderr, "Couldn't allocate memory for taskBuf.\n");
                exit(-1);
            }

            fread(taskBuf, sizeof(char), length, pKeysTasksFile);   // reading task string
            taskBuf[length] = '\0';
            break;
        }

        fread(task, sizeof(char), length, pKeysTasksFile);   // reading task string
    }

    fclose(pKeysTasksFile);
    return taskBuf;
}

void *realloc_mem(void* mem, size_t size, const char* varName)
{
        void* pTmp = realloc(mem, size);
        if(!pTmp)
        {
            fprintf(stderr, "Couldn't reallocate memory for %s.\n", varName);
            exit(-1);
        }

        return pTmp;
}

int find_event_num(char *deviceName)
{
    const unsigned char MAX_DEVICE_NAME = 255;
    char buf[MAX_DEVICE_NAME];
    char devNameTmp[MAX_DEVICE_NAME];
    FILE *pfile = NULL;
    char pathB[] = "/sys/class/input/event";  // Path Beginning
    char pathE[] = "/device/name";            // Path Ending

    int len = strlen(pathB) + 3 + strlen(pathE)  + 1;  // +3 for event0 to event999
                                                       // +1 for '\0'


    char *path = NULL;                             // Full path

    if(!(path = malloc(len)))
    {
        fprintf(stderr, "Couldn't allocate memory for path.\n");
        exit(-1);
    }

    for(int i = 0 ; ; ++i)
    {
        sprintf(path, "%s%d%s", pathB, i, pathE);
        // printf("cheacking \"%s\" ...\n", path);
        if(!(pfile = fopen(path, "r")))
        {
          //  printf("search is done.\n");
            break;
        }

        fgets(buf, MAX_DEVICE_NAME, pfile);
        buf[strlen(buf) - 1] = '\0';


        for(int i = 0 ; buf[i] ; ++i)
            buf[i] = toupper(buf[i]);

        for(int i = 0 ;  ; ++i)
        {
            if(deviceName[i] == '\0')
            {
                devNameTmp[i] = '\0';
                break;
            }

            devNameTmp[i] = toupper(deviceName[i]);
        }

        if(strstr(buf, devNameTmp))
        {
            // Device found
            free(path);
            return i;   // return event number
        }

        fclose(pfile);
    }

    free(path);
    return -1;
}

char *find_device(char *deviceName)
{
    int eventNum = 0;

    char pathB[] = "/dev/input/event"; // Path Beginning
    char *path = NULL;

     if((eventNum = find_event_num(deviceName)) == -1)
     {
         fprintf(stderr, "%s device NOT found.\n", deviceName);
         exit(-1);
     }

    if(!(path = malloc(strlen(pathB + 3 + 1))))     // +3 for event0-999 & +1 for '\0';
    {
        fprintf(stderr, "Couldn't allocate memory for path.\n");
        exit(-1);
    }

    sprintf(path, "%s%d", pathB, eventNum);

    return path;    // Don't forget to free
}

