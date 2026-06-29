#include <stdio.h>
#include <string.h>

void win(void) { puts("HTB{golden_pwn}"); }
void vuln(void) { char buffer[32]; gets(buffer); }
int main(void) { vuln(); }
