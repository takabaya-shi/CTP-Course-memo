# Pwn-Rev-CheatSheet
ChaetSheet for Pwn Reversing of CTF
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

### gdb-peda
- gdb -q ./file
- disas main   
main関数を逆アセンブル
### よく見るかたまり
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
#### 覚えておきたい
- アドレス   
`0x7fffff...`はスタックのアドレス。`0x555555...`はスタックのアドレス、であることが多い(?)。
