#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <intrin.h>
#include <windows.h>
#include <mmsystem.h>
#pragma comment(lib, "winmm.lib")

#define SIZE 21
#define FLAGLEN 50
uint8_t XOR[FLAGLEN] = {
    0x09,
    0x40,
    0x11,
    0xe4,
    0x1c,
    0x81,
    0x92,
    0xdb,
    0x0b,
    0x75,
    0x26,
    0x6a,
    0x2f,
    0x7f,
    0xdd,
    0xd2,
    0x52,
    0x21,
    0x76,
    0x9f,
    0xdf,
    0x8e,
    0x8f,
    0xcd,
    0x9f,
    0x84,
    0x61,
    0x3f,
    0x6d,
    0x7a,
    0x87,
    0x1e,
    0x21,
    0x99,
    0xc7,
    0x65,
    0xdc,
    0xc8,
    0x4a,
    0x22,
    0x7d,
    0x28,
    0x64,
    0x69,
    0xdc,
    0x20,
    0x34,
    0xed,
    0xfb,
    0xd7,
};

typedef struct
{
    uint8_t command;
    uint8_t note;
    uint8_t velocity;
    uint8_t unused;
} midi_message;

#define NOP() __nop()
#define XOR_NOPS() \
    NOP();         \
    NOP();         \
    NOP();         \
    NOP();         \
    NOP();         \
    NOP();         \
    NOP();

#define NOTE(n, v)            \
    NOP();                    \
    NOP();                    \
    g_message.command = 0x90; \
    g_message.note = n;       \
    g_message.velocity = v;   \
    g_message.unused = 0;     \
    XOR_NOPS();               \
    NOP();

midi_message g_message = {0x90, 0, 0, 0};

typedef void (*cell_t)();
#include "gen.c"

int main(int argc, char **argv)
{
    if (argc < 2)
    {
        printf("Usage: %s <prompt>\n", argv[0]);
        return 1;
    }

    if (strlen(argv[1]) != FLAGLEN)
    {
        printf("You should work on the length of your prompt!\n");
        return 1;
    }

    HMIDIOUT device;
    int status = midiOutOpen(&device, 0, 0, 0, CALLBACK_NULL);
    if (status != MMSYSERR_NOERROR)
    {
        printf("Failed to open MIDI device.\n");
        return 1;
    }

    int cur = 1 + SIZE; // (1, 1)

    for (int i = 0; i < FLAGLEN; i++)
    {
        uint8_t c = argv[1][i] ^ XOR[i];
        for (int j = 0; j < 4; j++)
        {
            switch (c & 3)
            {
            case 0: // up
                cur -= SIZE;
                break;
            case 1: // right
                cur += 1;
                break;
            case 2: // down
                cur += SIZE;
                break;
            case 3: // left
                cur -= 1;
                break;
            }

            cells[cur]();
            midiOutShortMsg(device, *(uint32_t *)&g_message);
            Sleep(30); // let tone play for a bit

            c >>= 2;
        }
    }

    Sleep(1000); // let the last note play
    midiOutReset(device);
    midiOutClose(device);

    if (cur == (SIZE * SIZE) - SIZE - 2)
    { // (SIZE - 1, SIZE - 1)
        printf("That was beautiful!\n");
        return 0;
    }

    printf("I think you should work on your music.\n");
    return 1;
}