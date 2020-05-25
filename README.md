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
