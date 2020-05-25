# Pwn-Rev-CheatSheet
ChaetSheet for Pwn Reversing of CTF
## 表層解析
- file
- strings
## 動的解析
- ./file (引数)
引数を変えてみて、入力に対して出力が一対一かどうか確認
## 静的解析
### radare2
- radare2 ./binary
- afl   
関数の一覧を表示
- pdf @main   
main関数を逆アセンブル
