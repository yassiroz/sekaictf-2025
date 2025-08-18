#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

char game_name[0x60];

__attribute__((constructor)) void flush_buf() {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
}

void puts_blue(char *str) {
    printf("\033[34m%s\033[0m\n", str);
}

int main(int argc, char **argv) {
    short level_rewards[10] = {0, 100, 200, 300, 400, 500, 600, 700, 800, 1337};
    int level;
    unsigned short reward;

    puts_blue(" _______  __   __  _______  ______   _______  _______  _______  ______     _______  _______  __   __  _______ \n|       ||  | |  ||       ||      | |   _   ||       ||       ||      |   |       ||   _   ||  |_|  ||       |\n|   _   ||  | |  ||_     _||  _    ||  |_|  ||_     _||    ___||  _    |  |    ___||  |_|  ||       ||    ___|\n|  | |  ||  |_|  |  |   |  | | |   ||       |  |   |  |   |___ | | |   |  |   | __ |       ||       ||   |___ \n|  |_|  ||       |  |   |  | |_|   ||       |  |   |  |    ___|| |_|   |  |   ||  ||       ||       ||    ___|\n|       ||       |  |   |  |       ||   _   |  |   |  |   |___ |       |  |   |_| ||   _   || ||_|| ||   |___ \n|_______||_______|  |___|  |______| |__| |__|  |___|  |_______||______|   |_______||__| |__||_|   |_||_______|");

    puts("Welcome to the Outdated Game!");
    printf("Here's a little bit of helpful information: %p\n", &main);
    puts("What would you like to name your game?");

    // control some global variable
    fgets(game_name, sizeof(game_name), stdin);
    game_name[strcspn(game_name, "\n")] = 0; // Remove newline character

    puts("Great! Your game is named:");
    puts(game_name);

    puts("Now, I am feeling generous today, so I'll let you change the reward for one level.");
    puts("Which level do you want to change?");

    // get signed number from user
    scanf("%d%*c", &level);

    puts("What reward do you want to set for this level?");
    scanf("%hu%*c", &reward);

    // oob write 2-byte value using signed number as idx onto stack
    level_rewards[level] = reward;

    // enabling function call
    printf("You have set the reward for level %d to %hu in your game %s.\n", level, reward, game_name);

    // exploitative function call 1 - gp-controlled arg
    puts("Thanks for playing! Come again!");

    // exploitative function call 2 - exit()
    exit(0);
}