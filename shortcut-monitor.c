// Detect the shortcut
#include<stdio.h>
#include<stdbool.h>                    // true, false
#include<string.h>                     // string functions (str***())
#include<stdlib.h>                     // malloc(), realloc(), system()
#include <fcntl.h>                     // open()
#include<unistd.h>                     // read(), write()
#include<linux/input.h>                // for struct input_event

#define TASK_SIZE      256           // Maximum number of characters for a task array
#define MAX_KEYSCOMBO  8             // Maximum number of keys pressed in combination at once
#define MAX_USER       64            // Maximum number of characters in USERNAME enviroment variable

struct Keys
{
    unsigned char kCodes[MAX_KEYSCOMBO];          // Array of binary representation of the key
    unsigned char kSize;                          // Size of the array
    bool kComboFlag;                              // Keys combination  flag
};

char *search_combo(struct Keys *KeyCodes);
void keys_combo(struct input_event *pEvent, struct Keys *KeysCodes);
void *realloc_mem(void* mem,size_t size, const char* varName);

int main(int argc, char *argv[])
{
    struct Keys *KeysInfo = malloc(sizeof(struct Keys));
    const char CHUNCK = sizeof(struct input_event);
    struct input_event *pEvent = NULL;
    char **pKeys = NULL;
    char *exeTask = NULL;
    char *unSudoTask = NULL;
    int KBfd = -1;
    unsigned char length = 0,
                  len   = 0;

    if(argc == 3)
    {
        len = strnlen(argv[1], MAX_USER) + 10;
        if((KBfd = open(argv[2], O_RDONLY)) == -1)
        {
            fprintf(stderr, "Couldn't open Keyboard event file for reading.\n");
            return -1;
        }
    }
    else
    {
        fprintf(stderr, "Usage: sudo ./shortCutMonitor $USER  Path_To_Keyboard_Event_File\n");
        return -1;
    }

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
                printf("Executing: %s\n", exeTask);
                length = strnlen(exeTask, TASK_SIZE);
                unSudoTask =  realloc_mem(unSudoTask, length + len, "unSudoTask");
                sprintf(unSudoTask, "sudo -u %s %s",argv[1], exeTask);  // turn off sudo
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
