#include<stdio.h>
#include<string.h>                     // string functions (str***())
#include<stdlib.h>                     // malloc(), realloc(), system()
#include<stdbool.h>                    // true, false
#include<ctype.h>                      // toupper()
#include <fcntl.h>                     // open()
#include<unistd.h>                     // read(), write()
#include<linux/input.h>                // for struct input_event
#include<termios.h>                    // tcgetattr(), tcsetattr(), tcflush(), struct termios


#define MAX_KEYSCOMBO   8            // Maximum number of keys pressed in combination at once
#define MAX_CODE        3            // Maximum number of characters for a code in decimal
#define MAX_KEY        32            // Maximum number of characters for a key in text format
#define TASK_SIZE      285           // Maximum number of characters for a task array
#define MAX_PATH       256           // Maximum number of characters for file name

struct Keys
{
    unsigned char *kCodes;            // Array of binary representation of the key
    unsigned char kSize;              // Size of the array
    bool kComboFlag;                  // Keys combination flag status
};

const char CHUNCK = sizeof(struct input_event);
struct Keys *KeysInfo = NULL;
struct input_event *pEvent = NULL;
char *SCExist = NULL;
char **pKeys = NULL;            // hold text and numeric representation of keys combination
char task[TASK_SIZE];
char key[MAX_KEY];
char choice = 'Y';
int KBfd = 0;


// Get keys combination in binary form to kCodes array
void keys_combo(struct input_event *pEvent, struct Keys *KeysInfo);
// Translate binary key code its text form
void key_identity(int code, char* key);
// Generate text and binary
char **str_keys(struct Keys *KeysInfo);
// Save keys combination with its task
void save_2_file(struct Keys *KeyCodes, char *task);
// Lock/Unlock terminal reading from keyboard
void terminal_input(bool inputStatus);
// Search shortcut in file
char *search_combo(struct Keys *KeyCodes);
// Edit task of existing shortcut from file
void edit_sc_file(struct Keys *KeysInfo);
// Remove shortcut from file
void remove_sc_file(struct Keys *KeysInfo);
// Warpper function for realloc()
void *realloc_mem(void* mem,size_t size, const char* varName);
// Message to enter keys combination
void input_message(void);
// Discard keys stored in keyboard file buffer
void flush_KB(void);
 // choose an option
int options(void);
// List all shortcuts stored in file
void list_sc(void);
// Add new shortcut
void add_sc(void);
// Edit exist shortcut in the file
void edit_sc(void);
// Remove shortcut
void remove_sc(void);

int main(int argc, char *argv[])
{
    if(argc == 2)
    {
        if((KBfd = open(argv[1], O_RDONLY)) == -1)
        {
            fprintf(stderr, "Couldn't open Keyboard event file \"%s\" for reading.\n", argv[1]);
            return -1;
        }
    }
    else
    {
        fprintf(stdout, "Usage: sudo %s Path_to_Keyboard_Event_file\n", argv[0]);
        return -1;
    }

    for(;;)
    {
        choice = options();

        if(choice == 1)
            list_sc();
        else if(choice == 2)
            add_sc();
        else if(choice == 3)
            edit_sc();
        else if(choice == 4)
            remove_sc();
        else
            break;
    }

    printf("\e[1;1H\e[2J"); // clear the screen

    close(KBfd);

    if(isdigit(choice))
    {
        free(pKeys[0]);
        free(pKeys[1]);
        free(pKeys);
    }

    return 0;
}


void keys_combo(struct input_event *pEvent, struct Keys *KeysInfo)
{
    static unsigned char counter = 0;
    static unsigned char lastCode = 0xff;   // Default value
    static bool keyCombo = false;
    static bool comboBreak = true;      // Break the rest of the keys to printed after the first key relasesd

    if(pEvent->type == 1)
        switch(pEvent->value)
        {
            case 0:
                KeysInfo->kSize = counter;

                if(counter < 2 || !comboBreak)
                {
                   KeysInfo->kComboFlag = false;
                   input_message();
                }
                else
                    KeysInfo->kComboFlag = true;

                lastCode = pEvent->code;
                comboBreak = false;
                counter = 0;
                break;
            case 1:
                KeysInfo->kCodes[counter++] = pEvent->code;
                KeysInfo->kSize = counter;
                KeysInfo->kComboFlag = false;
                comboBreak = true;
                break;
        }
    else
        KeysInfo->kComboFlag = false;
}


void key_identity(int code, char *key)
{
    switch(code)
    {
        case 1  : strcpy(key, "ESC"); break;
        case 59 : strcpy(key, "F1"); break;
        case 60 : strcpy(key, "F2"); break;
        case 61 : strcpy(key, "F3"); break;
        case 62 : strcpy(key, "F4"); break;
        case 63 : strcpy(key, "F5"); break;
        case 64 : strcpy(key, "F6"); break;
        case 65 : strcpy(key, "F7"); break;
        case 66 : strcpy(key, "F8"); break;
        case 67 : strcpy(key, "F9"); break;
        case 68 : strcpy(key, "F10"); break;
        case 70 : strcpy(key, "ScrollLock"); break;
        case 87 : strcpy(key, "F11"); break;
        case 88 : strcpy(key, "F12"); break;
        case 110: strcpy(key, "INS"); break;
        case 111: strcpy(key, "DEL"); break;
        case 102: strcpy(key, "HOME"); break;
        case 107: strcpy(key, "END"); break;
        case 104: strcpy(key, "PGUP"); break;
        case 109: strcpy(key, "PGDN"); break;
        case 114: strcpy(key, "VolumeDown"); break;
        case 115: strcpy(key, "VolumeUp"); break;
        case 41 : strcpy(key, "`"); break;
        case 2  : strcpy(key, "1"); break;
        case 3  : strcpy(key, "2"); break;
        case 4  : strcpy(key, "3"); break;
        case 5  : strcpy(key, "4"); break;
        case 6  : strcpy(key, "5"); break;
        case 7  : strcpy(key, "6"); break;
        case 8  : strcpy(key, "7"); break;
        case 9  : strcpy(key, "8"); break;
        case 10 : strcpy(key, "9"); break;
        case 11 : strcpy(key, "0"); break;
        case 12 : strcpy(key, "-"); break;
        case 13 : strcpy(key, "="); break;
        case 14 : strcpy(key, "BACKSPACE"); break;
        case 69 : strcpy(key, "NUMLOCK"); break;
        case 98 : strcpy(key, "/(KEYPAD)"); break;
        case 99 : strcpy(key, "SYSRQ/PRTSC"); break;
        case 119: strcpy(key, "BREAK/PAUSE"); break;
        case 55 : strcpy(key, "*(KEYPAD)"); break;
        case 74 : strcpy(key, "-(KEYPAD)"); break;
        case 15 : strcpy(key, "TAB"); break;
        case 16 : strcpy(key, "Q"); break;
        case 17 : strcpy(key, "W"); break;
        case 18 : strcpy(key, "E"); break;
        case 19 : strcpy(key, "R"); break;
        case 20 : strcpy(key, "T"); break;
        case 21 : strcpy(key, "Y"); break;
        case 22 : strcpy(key, "U"); break;
        case 23 : strcpy(key, "I"); break;
        case 24 : strcpy(key, "O"); break;
        case 25 : strcpy(key, "P"); break;
        case 26 : strcpy(key, "["); break;
        case 27 : strcpy(key, "]"); break;
        case 28 : strcpy(key, "ENTER"); break;
        case 58 : strcpy(key, "CAPSLOCK"); break;
        case 30 : strcpy(key, "A"); break;
        case 31 : strcpy(key, "S"); break;
        case 32 : strcpy(key, "D"); break;
        case 33 : strcpy(key, "F"); break;
        case 34 : strcpy(key, "G"); break;
        case 35 : strcpy(key, "H"); break;
        case 36 : strcpy(key, "J"); break;
        case 37 : strcpy(key, "K"); break;
        case 38 : strcpy(key, "L"); break;
        case 39 : strcpy(key, ";"); break;
        case 40 : strcpy(key, "'"); break;
        case 43 : strcpy(key, "\\"); break;
        case 42 : strcpy(key, "LeftSHIFT"); break;
        case 86 : strcpy(key, "<"); break;
        case 44 : strcpy(key, "Z"); break;
        case 45 : strcpy(key, "X"); break;
        case 46 : strcpy(key, "C"); break;
        case 47 : strcpy(key, "V"); break;
        case 48 : strcpy(key, "B"); break;
        case 49 : strcpy(key, "N"); break;
        case 50 : strcpy(key, "M"); break;
        case 51 : strcpy(key, ",(COMMA)"); break;
        case 52 : strcpy(key, ".(DOT)"); break;
        case 53 : strcpy(key, "/"); break;
        case 54 : strcpy(key, "RightSHIFT"); break;
        case 29 : strcpy(key, "LeftCTRL"); break;
        case 125: strcpy(key, "ApplicationLauncher"); break;
        case 56 : strcpy(key, "LeftALT"); break;
        case 57 : strcpy(key, "SPACE"); break;
        case 100: strcpy(key, "RightALT"); break;
        case 127: strcpy(key, "RightClickMouseKey"); break;
        case 97 : strcpy(key, "RightCTRL"); break;
        case 105: strcpy(key, "LEFT"); break;
        case 103: strcpy(key, "UP"); break;
        case 108: strcpy(key, "DOWN"); break;
        case 106: strcpy(key, "RIGHT"); break;
        case 82 : strcpy(key, "0(KEYPAD)"); break;
        case 79 : strcpy(key, "1(KEYPAD)"); break;
        case 80 : strcpy(key, "2(KEYPAD)"); break;
        case 81 : strcpy(key, "3(KEYPAD)"); break;
        case 75 : strcpy(key, "4(KEYPAD)"); break;
        case 76 : strcpy(key, "5(KEYPAD)"); break;
        case 77 : strcpy(key, "6(KEYPAD)"); break;
        case 71 : strcpy(key, "7(KEYPAD)"); break;
        case 72 : strcpy(key, "8(KEYPAD)"); break;
        case 73 : strcpy(key, "9(KEYPAD)"); break;
        case 83 : strcpy(key, ".(DOT)(KEYPAD)"); break;
        case 96 : strcpy(key, "ENTER(KEYPAD)"); break;
        case 78 : strcpy(key, "+(KEYPAD)"); break;
        default : strcpy(key, "UNKOWN"); break;
    }
}

char **str_keys(struct Keys *KeyCodes)
{
    char pKey[MAX_KEY];
    char pCode[MAX_CODE];

    char **pKeys = malloc(2*sizeof(char *));
    if(!pKeys)
    {
        fprintf(stderr, "Couldn't allocate memory for pKeys.\n");
        exit(-2);
    }

    char *pKeysCombo = NULL;
    char *pCodesCombo = NULL;
    char *pTmp = NULL;
    size_t length = 0,
           len = 0;

    key_identity(KeyCodes->kCodes[0], pKey);
    length = strnlen(pKey, MAX_KEY) + 2;  // +2 for '+' and '\0'
    pKeysCombo = malloc(length);

    snprintf(pCode, MAX_CODE, "%d", KeyCodes->kCodes[0]);
    len = strnlen(pCode, MAX_CODE) + 2;  // +2 for '+' and '\0'
    pCodesCombo = malloc(len);

    if(!pKeysCombo || !pCodesCombo)
    {
        fprintf(stderr, "failed to allocate memory for pKeysCombo or pCodesCombo or both\n");
        exit(-1);
    }

    snprintf(pKeysCombo, MAX_KEY + 1, "%s+", pKey);
    snprintf(pCodesCombo, MAX_CODE + 1, "%s+", pCode);

    for(size_t i = 1 ; i < KeyCodes->kSize ; ++i)
    {
        key_identity(KeyCodes->kCodes[i], pKey);
        snprintf(pCode, MAX_CODE, "%d", KeyCodes->kCodes[i]);
        length += strnlen(pKey, MAX_KEY) + 1;    // +1 for '+'
        len    += strnlen(pCode, MAX_CODE) + 1;  // +1 for '+'

        pTmp = realloc(pKeysCombo, length);
        if(!pTmp)
        {
            free(pKeysCombo);
            fprintf(stderr, "Failed to reallocate memory for pKeysCombo.\n");
            exit(-2);
        }
        pKeysCombo = pTmp;

        pTmp = realloc(pCodesCombo, len);
        if(!pTmp)
        {
            free(pCodesCombo);
            fprintf(stderr, "Failed to reallocate memory for pCodesCombo.\n");
            exit(-2);
        }
        pCodesCombo = pTmp;

        strncat(pKeysCombo, pKey, MAX_KEY);
        strncat(pCodesCombo, pCode, MAX_CODE);
        strcat(pKeysCombo, "+");
        strcat(pCodesCombo, "+");
    }

    pKeysCombo[length - 2] = '\0';      // Remove the last '+'
    pCodesCombo[len - 2] = '\0';        // Remove the last '+'
    pKeys[0] = pCodesCombo;
    pKeys[1] = pKeysCombo;

    return pKeys;
}

void save_2_file(struct Keys *KeyCodes, char *task)
{
    FILE *pSaveFile = fopen("KEYSTASKS.sc", "ab");
    if(!pSaveFile)
    {
        fprintf(stderr, "Couldn't open kEYSTASKS.sc for writing.\n");
        exit(-1);
    }

    int alLength = 2*sizeof(char) + KeyCodes->kSize + strlen(task);
    unsigned char buf[alLength];
    unsigned char taskLen = strlen(task);
    unsigned char fwLen = 0;

    buf[0] = '\0';

    strncat(buf, &KeyCodes->kSize, 1);
    strncat(buf, KeyCodes->kCodes, KeyCodes->kSize);
    strncat(buf, &taskLen, 1);
    strncat(buf, task, taskLen);

    fwLen = fwrite(buf, sizeof(char), alLength, pSaveFile);
    if(fwLen == alLength)
        printf("Saved successfully\n");
    else
    {
        fprintf(stderr, "ERROR : keys combination and the task not fully written to the file (written %d byted out of %d).\n", fwLen, alLength);
        exit(-1);
    }
    fclose(pSaveFile);
}

void terminal_input(bool inputStatus)
{
    struct termios attr;
    tcgetattr(0, &attr);

    if(inputStatus)
    {
        tcflush(0, TCIFLUSH);
        attr.c_lflag |= ECHO;
    }
    else
        attr.c_lflag &= ~ECHO;

    tcsetattr(0, TCSANOW, &attr);
}

char *search_combo(struct Keys *KeyCodes)
{
    FILE *pKeysTasksFile = fopen("KEYSTASKS.sc", "r");
    if(!pKeysTasksFile)
    {
        pKeysTasksFile = fopen("KEYSTASKS.sc", "w");
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

        fread(&length, sizeof(char), 1, pKeysTasksFile);


        if(bingo)
        {
            if(!(taskBuf = malloc(length + 1) ))
            {
                fprintf(stderr, "Couldn't allocate memory for taskBuf.\n");
                exit(-1);
            }

            fread(taskBuf, sizeof(char), length, pKeysTasksFile);
            taskBuf[length] = '\0';
            break;
        }

        fread(task, sizeof(char), length, pKeysTasksFile);
    }

    fclose(pKeysTasksFile);
    return taskBuf;
}

void edit_sc_file(struct Keys *KeyCodes)
{
    unsigned long long counter = 0;

    FILE *pKeysTasksFile = fopen("KEYSTASKS.sc", "r");
    FILE *pTmpFile = fopen("KEYSTASKSTMP.sc", "w");

    if(!pKeysTasksFile || !pTmpFile)
    {
        fprintf(stderr, "Couldn't open KEYSTASKS.sc for reading or KEYSTASKSTMP.sc for writing\n");
        exit(-1);
    }

    char newTask[TASK_SIZE];
    char codesBuf[MAX_KEYSCOMBO];
    char taskBuf[TASK_SIZE];
    char *tmpFileBuf = NULL;

    unsigned char length = 0;
    size_t alLength = 0;
    bool bingo = false;
    unsigned char newTaskLen = 0;

    if(!(tmpFileBuf = malloc(1)))
    {
        fprintf(stderr, "Couldn't allocate memory for tmpFileBuf.\n");
        exit(-1);
    }

    printf("Enter the new task (less than %d charcters) : ", TASK_SIZE - 29);
    fgets(newTask, TASK_SIZE, stdin);

    newTask[strnlen(newTask, TASK_SIZE)] = '\0';   // Remove '\n' character

    // strcat(newTask, " 1> /dev/null 2> /dev/null &");   // run the task as background process to not block next shortcut...
                                                       // ...and redirect all output to null file

    printf("save changes to file (Y/N)? ");
    scanf("%c", &choice);
    getchar();

    if(toupper(choice) != 'Y')
        return;

    newTaskLen = strnlen(newTask, TASK_SIZE) - 1;

    tmpFileBuf[0] = '\0';

    for(; !(feof(pKeysTasksFile)) ; )
    {
        fread(&length, sizeof(char), 1, pKeysTasksFile);    // number of codes array
        fread(codesBuf, sizeof(char), length, pKeysTasksFile);

        alLength += length + 1;
        tmpFileBuf = realloc_mem(tmpFileBuf, alLength, "tmpFileBuf");

        strncat(tmpFileBuf, &length, 1);
        strncat(tmpFileBuf, codesBuf, length);

        if(length == KeyCodes->kSize)
        {
            if(strncmp(codesBuf, KeyCodes->kCodes, length) == 0)
            {
                alLength += newTaskLen + 1;
                tmpFileBuf = realloc_mem(tmpFileBuf, alLength, "tmpFileBuf");

                bingo = true;   // Bingo !! .. found it
                strncat(tmpFileBuf, &newTaskLen, 1);
                strncat(tmpFileBuf, newTask, newTaskLen);
            }

        }

        fread(&length, sizeof(char), 1, pKeysTasksFile);
        fread(taskBuf, sizeof(char), length, pKeysTasksFile);

       if(!bingo)
       {
           alLength += length + 1;
           tmpFileBuf = realloc_mem(tmpFileBuf, alLength, "tmpFileBuf");
           strncat(tmpFileBuf, &length, 1);
           strncat(tmpFileBuf, taskBuf, length);

       }
        if(!(feof(pKeysTasksFile)))
            fwrite(tmpFileBuf, sizeof(char), alLength, pTmpFile);

        tmpFileBuf = realloc_mem(tmpFileBuf, 1, "tmpFileBuf");
        tmpFileBuf[0] = '\0';
        alLength = 0;

       bingo = false;
    }

    free(tmpFileBuf);
    fclose(pKeysTasksFile);
    fclose(pTmpFile);

    if(remove("KEYSTASKS.sc"))
    {
        fprintf(stderr, "Couldn't remove the KEYSTASKS.sc file.\n");
        exit(-1);
    }

    if(rename("KEYSTASKSTMP.sc", "KEYSTASKS.sc"))
    {
        fprintf(stderr, "Couldn't rename KEYSTASKSTMP.sc file to KEYSTASKS.sc.\n");
        exit(-1);
    }

    printf("Shortcuts updated successfully.\n");
}

void remove_sc_file(struct Keys *KeyCodes)
{
    FILE *pKeysTasksFile = fopen("KEYSTASKS.sc", "r");
    FILE *pTmpFile = fopen("KEYSTASKSTMP.sc", "w");

    if(!pKeysTasksFile || !pTmpFile)
    {
        fprintf(stderr, "Couldn't open KEYSTASKS.sc for reading or KEYSTASKSTMP.sc for writing\n");
        exit(-1);
    }

    char codesBuf[MAX_KEYSCOMBO];
    char taskBuf[TASK_SIZE];
    unsigned char lengthC = 0, lengthT = 0;
    char *tmpFileBuf = NULL;

    if(!(tmpFileBuf = malloc(1)))
    {
        fprintf(stderr, "Couldn't allocate memory for tmpFileBuf.\n");
        exit(-1);
    }

    tmpFileBuf[0] = '\0';

    for(; !(feof(pKeysTasksFile)) ;)
    {
        fread(&lengthC, sizeof(char), 1, pKeysTasksFile);    // number of codes array
        fread(codesBuf, sizeof(char), lengthC, pKeysTasksFile);
        fread(&lengthT, sizeof(char), 1, pKeysTasksFile);
        fread(taskBuf, sizeof(char), lengthT, pKeysTasksFile);

        if(lengthC == KeyCodes->kSize)
            if(strncmp(codesBuf, KeyCodes->kCodes, lengthC) == 0)
                continue;

        tmpFileBuf = realloc_mem(tmpFileBuf, lengthC + lengthT + 2, "tmpFileBuf");

         strncat(tmpFileBuf, &lengthC, 1);
         strncat(tmpFileBuf, codesBuf, lengthC);
         strncat(tmpFileBuf, &lengthT, 1);
         strncat(tmpFileBuf, taskBuf, lengthT);

         if(!(feof(pKeysTasksFile)))
         {
            fwrite(tmpFileBuf, lengthC + lengthT + 2, 1, pTmpFile);
            tmpFileBuf[0] = '\0';
         }
         else
             break;

    }

    fclose(pKeysTasksFile);
    fclose(pTmpFile);

    if(remove("KEYSTASKS.sc"))
    {
        fprintf(stderr, "Couldn't remove the KEYSTASKS.sc file.\n");
        exit(-1);
    }

    if(rename("KEYSTASKSTMP.sc", "KEYSTASKS.sc"))
    {
        fprintf(stderr, "Couldn't rename KEYSTASKSTMP.sc file to KEYSTASKS.sc.\n");
        exit(-1);
    }

    printf("Shortcuts updated successfully.\n");

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

void input_message(void)
{
    printf("\e[1;1H\e[2J"); // clear the screen
    printf("Enter keys combination :\n");
}

// Discard keys stored in keyboard file buffer
void flush_KB(void)
{
    FILE *pfile = NULL;
    char buf[MAX_PATH];

    close(KBfd);

    pfile = popen("echo \"/dev/input/by-path/\"$(ls /dev/input/by-path | grep kbd)", "r");
    fgets(buf, MAX_PATH, pfile);
    pclose(pfile);

    buf[strnlen(buf, MAX_PATH) - 1] = '\0';
    KBfd = open(buf, O_RDONLY);
    if(KBfd == -1)
    {
        fprintf(stderr, "Couldn't open Keyboard event file \"%s\"for reading.\n", buf);
        exit(-1);
    }

}

int options(void)
{
    char choice = '\0';
    printf("\e[1;1H\e[2J"); // clear the screen
    printf("\n\n     SHORTCUT PROGRAM\n");
    printf("   '.'.'.'.'.'.'.'.'.'.\n\n");
    printf("    1- List all shortcuts.\n");
    printf("    2- Add new shortcut.\n");
    printf("    3- Edit exist shortcut.\n");
    printf("    4- Remove Shortcut.\n");
    printf("    5- Exit.\n\n\n");

    printf("choose from 1 - 5 : ");
    scanf("%hhd", &choice);
    getchar();

    // Flush unwanted keys combinations
    flush_KB();

    return choice;
}

void list_sc(void)
{
    FILE *pKeysTasksFile = NULL;
    char codesBuf[MAX_KEYSCOMBO];
    char taskBuf[TASK_SIZE];
    unsigned char lengthC = 0, lengthT = 0;
    char *tmpFileBuf = NULL;
    unsigned int counter = 0;

    struct Keys *KeysInfo = NULL;

    if(!(pKeysTasksFile = fopen("KEYSTASKS.sc", "r")))
    {
        printf("\e[1;1H\e[2J"); // clear the screen
        printf("\n\n\n           THERE IS NO SHORTCUTS !\n");
        printf("\n\n\n\n         Press Enter ...\n");
        getchar();
        return;
    }

    if(!(KeysInfo = malloc(sizeof(struct Keys))))
    {
        fprintf(stderr, "Couldn't allocate memory for KeysInfo.\n");
        exit(-1);
    }

    if(!pKeysTasksFile)
    {
        fprintf(stderr, "Couldn't open KEYSTASKS.sc for reading.\n");
        exit(-1);
    }

    printf("\e[1;1H\e[2J"); // clear the screen

    printf("\n");
    printf(".---.---------------------------------.--------------------------------------------.\n");
    printf("|No.|             %s            |                     %s                   |\n", "SHORTCUT", "TASK");
    printf("'---'---------------------------------'--------------------------------------------'\n");
    for(; !(feof(pKeysTasksFile)) ; )
    {
        fread(&lengthC, sizeof(char), 1, pKeysTasksFile);    // number of codes array
        fread(codesBuf, sizeof(char), lengthC, pKeysTasksFile);
        fread(&lengthT, sizeof(char), 1, pKeysTasksFile);
        fread(taskBuf,  sizeof(char), lengthT, pKeysTasksFile);

        taskBuf[lengthT] = '\0';

        KeysInfo->kCodes = codesBuf;
        KeysInfo->kSize  = lengthC;
        pKeys = str_keys(KeysInfo);

        if(!(feof(pKeysTasksFile)))
            printf("%3d |  %-30s |  %s\n", ++counter, pKeys[1], taskBuf);
    }

    printf("\n\n\n\n         Press Enter ...\n");
    getchar();

    fclose(pKeysTasksFile);
}

void add_sc(void)
{
    KeysInfo = malloc(sizeof(struct Keys));
    pEvent = malloc(sizeof(CHUNCK));
    KeysInfo->kCodes = malloc(MAX_KEYSCOMBO);

    do
    {

        for(;;)
        {
            terminal_input(false);       // Lock terminal reading from keyboard
            read(KBfd, pEvent, CHUNCK);

            // New key pressed
            if(pEvent->type == 1 && pEvent->value == 1)
            {
                key_identity(pEvent->code, key);
                printf("%s+", key);
                fflush(stdout);             // Force to write it to stdout
            }

            keys_combo(pEvent, KeysInfo);

            if(KeysInfo->kComboFlag)
            {
                terminal_input(true);    // Unlock terminal to read from keyboard

                pKeys = str_keys(KeysInfo);

                if((SCExist = search_combo(KeysInfo)))
                {
                    printf("\n-------------------------------------\n");
                    printf("\n\n      USED SHORTCUT\n");
                    printf("   '.'.'.'.'.'.'.'.'.'\n\n");

                    printf("SHORTCUT        : %s\n", pKeys[1]);
                    printf("TASK            : %s\n\n\n", SCExist);

                    printf("\n\nEnter another shortcut (Y/N)? ");
                    scanf("%c", &choice);

                    free(SCExist);
                    break;

                    // Flush keys combination left in the input buffer
                    flush_KB();
                }
                printf("\n");

                printf("Enter the task for the key combination (less than %d characters) : ", TASK_SIZE - 29);
                fgets(task, TASK_SIZE, stdin);

                task[strnlen(task, TASK_SIZE) - 1] = '\0';
                strcat(task, " 1> /dev/null 2> /dev/null &");     // run the task as background process to not block next shortcut...
                                                                  // ...and redirect all output to null file

                printf("\nKeys combinations    : %s", pKeys[1]);
                printf("\nTask                 : %s\n", task);

                printf("\nSave to the file (Y/N)? ");
                scanf("%c", &choice);

                getchar();

                if(toupper(choice) == 'Y')
                    save_2_file(KeysInfo, task);

                printf("\n\nAdd another shortcut (Y/N)? ");
                scanf("%c", &choice);
                getchar();

                // Flush keys combination left in the input buffer
                flush_KB();

                break;
            }

        }

    }while(toupper(choice) == 'Y');

    free(pEvent);
    free(KeysInfo->kCodes);
    free(KeysInfo);
}

void edit_sc(void)
{
    KeysInfo = malloc(sizeof(struct Keys));
    pEvent = malloc(sizeof(CHUNCK));
    KeysInfo->kCodes = malloc(MAX_KEYSCOMBO);

    do
    {
        for(;;)
        {
            terminal_input(false);       // Lock terminal reading from keyboard
            read(KBfd, pEvent, CHUNCK);

            // New key pressed
            if(pEvent->type == 1 && pEvent->value == 1)
            {
                key_identity(pEvent->code, key);
                printf("%s+", key);
                fflush(stdout);             // Force to write it to stdout
            }

            keys_combo(pEvent, KeysInfo);

            if(KeysInfo->kComboFlag)
            {
                terminal_input(true);    // Unlock terminal to read from keyboard

                // If shortcut exist
                if((SCExist = search_combo(KeysInfo)))
                {
                    printf("\n-------------------------------------\n");
                    printf("\n\n      USED SHORTCUT\n");
                    printf("   '.'.'.'.'.'.'.'.'.'\n\n");

                    pKeys = str_keys(KeysInfo);
                    printf("SHORTCUT        : %s\n", pKeys[1]);
                    printf("TASK            : %s\n\n\n", SCExist);

                    edit_sc_file(KeysInfo);
                    free(SCExist);

                }
                else
                {
                    printf("\n-------------------------------------\n");
                    printf("Shortcut not found !\n");
                }

                printf("\n\nEdit another shortcut (Y/N)? ");
                scanf("%c", &choice);
                getchar();

                // Flush keys combination left in the input buffer
                flush_KB();
                break;
            }
        }
    }while(toupper(choice) == 'Y');

    free(pEvent);
    free(KeysInfo->kCodes);
    free(KeysInfo);
}

void remove_sc(void)
{
    KeysInfo = malloc(sizeof(struct Keys));
    pEvent = malloc(sizeof(CHUNCK));
    KeysInfo->kCodes = malloc(MAX_KEYSCOMBO);

    do{

        for(;;)
        {
            terminal_input(false);       // Lock terminal reading from keyboard
            read(KBfd, pEvent, CHUNCK);

            // New key pressed
            if(pEvent->type == 1 && pEvent->value == 1)
            {
                key_identity(pEvent->code, key);
                printf("%s+", key);
                fflush(stdout);             // Force to write it to stdout
            }

            keys_combo(pEvent, KeysInfo);

            if(KeysInfo->kComboFlag)
            {
                terminal_input(true);    // Unlock terminal to read from keyboard

                if((SCExist = search_combo(KeysInfo)))
                {
                    printf("\n-------------------------------------\n");
                    printf("\n\n      USED SHORTCUT\n");
                    printf("   '.'.'.'.'.'.'.'.'.'\n\n");

                    pKeys = str_keys(KeysInfo);
                    printf("SHORTCUT        : %s\n", pKeys[1]);
                    printf("TASK            : %s\n\n\n", SCExist);

                    printf("Remove this shortcut (Y/N)? ");
                    scanf("%c", &choice);

                    if(toupper(choice) == 'Y')
                        remove_sc_file(KeysInfo);
                }
                else
                {
                    printf("\n-------------------------------------\n");
                    printf("Shortcut not found !\n");
                }

                printf("\n\nRemove another shortcut (Y/N)? ");
                scanf("%c", &choice);
                getchar();

                // Flush keys combination left in the input buffer
                flush_KB();

                break;
            }
        }
    }while(toupper(choice) == 'Y');

    free(pEvent);
    free(KeysInfo->kCodes);
    free(KeysInfo);
}
