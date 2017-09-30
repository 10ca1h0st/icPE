#!/usr/bin/python3
#-*- coding:utf-8 -*-
'''
一个查看dll文件的pe结构的工具
'''

import sys

filename = sys.argv[1]

'''
除了代表地址的字段要用10进制保存，其他都用bytes保存，即b'\x00'这种形式
'''
#定义一些PE头中的重要字段
offset_NT = 0
#NT Header
    #IMAGE_FILE_HEADER
Machine = b'\x00\x00'
NumberOfSections = b'\x00\x00'
SizeOfOptionalHeader = b'\x00\x00'
Characteristics = b'\x00\x00'
    #IMAGE_OPTIONAL_HEADER
offset_OPTIONAL_HEADER = 0
Magic = b'\x00\x00'
AddressOfEntryPoint = b'\x00\x00\x00\x00'
IMageBase = b'\x00\x00\x00\x00'
SectionAlignment = b'\x00\x00\x00\x00'
FileAlignment = b'\x00\x00\x00\x00'
SizeOfImage = b'\x00\x00\x00\x00'
SizeOfHeaders = b'\x00\x00\x00\x00'
Subsystem = b'\x00\x00'
NumberOfRvaAndSizes = b'\x00\x00\x00\x00'
DataDirectory = [{'rva':0,'size':b'\x00\x00\x00\x00'}]
#IMAGE_SECTION_HEADER
offset_SECTION_HEADER = 0
    #第一个节区头
Name_one = b'\x00\x00\x00\x00\x00\x00\x00\x00'
VirtualSize_one = b'\x00\x00\x00\x00'
VirtualAddress_one = 0
SizeOfRawData_one = b'\x00\x00\x00\x00'
PointerToRawData_one = 0
Characteristics_one_in_SECTION_HEADER = b'\x00\x00\x00\x00'
    #第二个节区头
offset_SECTION_HEADER_two = 0
Name_two = b'\x00\x00\x00\x00\x00\x00\x00\x00'
VirtualSize_two = b'\x00\x00\x00\x00'
VirtualAddress_two = 0
SizeOfRawData_two = b'\x00\x00\x00\x00'
PointerToRawData_two = 0
Characteristics_two_in_SECTION_HEADER = b'\x00\x00\x00\x00'
    #第三个节区头
offset_SECTION_HEADER_three = 0
Name_three = b'\x00\x00\x00\x00\x00\x00\x00\x00'
VirtualSize_three = b'\x00\x00\x00\x00'
VirtualAddress_three = 0
SizeOfRawData_three = b'\x00\x00\x00\x00'
PointerToRawData_three = 0
Characteristics_three_in_SECTION_HEADER = b'\x00\x00\x00\x00'



def little_endian(s):
    return s[::-1]

def byte2int(s):
    length = len(s)
    sum = 0
    for i,v in enumerate(s):
        sum = sum+v*16**((length-1-i)*2) if i<length-1 else sum+v
    return sum

def rva2raw(address):
    global VirtualAddress_one,VirtualAddress_two,VirtualAddress_three,\
    PointerToRawData_one,PointerToRawData_two,PointerToRawData_three
    if isinstance(address,bytes):
        address = byte2int(address)
    if address > VirtualAddress_one and address < VirtualAddress_two:
        return address-VirtualAddress_one+PointerToRawData_one
    elif address > VirtualAddress_two and address < VirtualAddress_three:
        return address-VirtualAddress_two+PointerToRawData_two
    else:
        return address-VirtualAddress_three+PointerToRawData_three
    return 0

def splitToSections():
    global offset_NT,offset_OPTIONAL_HEADER,NumberOfRvaAndSizes,offset_SECTION_HEADER,\
    offset_SECTION_HEADER_two,offset_SECTION_HEADER_three,\
    Name_one,Name_two,Name_three,VirtualAddress_one,VirtualAddress_two,VirtualAddress_three,\
    PointerToRawData_one,PointerToRawData_two,PointerToRawData_three
    with open(filename,'rb') as fp:
        s = fp.read()
        offset_NT = byte2int(little_endian(s[60:64]))
        #print(offset_NT)
        #print(s[offset_NT:offset_NT+4])
        if s[offset_NT:offset_NT+4] != b'\x50\x45\x00\x00':
            print('the file is not pe file')
        
        offset_OPTIONAL_HEADER = offset_NT+20+4
        #print(s[offset_OPTIONAL_HEADER:offset_OPTIONAL_HEADER+4])
        NumberOfRvaAndSizes = little_endian(s[offset_OPTIONAL_HEADER+92:offset_OPTIONAL_HEADER+96])
        #print(NumberOfRvaAndSizes)
        #print(byte2int(NumberOfRvaAndSizes))
        #print(byte2int(b'\x11\x12\x13'))
        offset_SECTION_HEADER = offset_OPTIONAL_HEADER+96+byte2int(NumberOfRvaAndSizes)*8
        offset_SECTION_HEADER_two = offset_SECTION_HEADER+40
        offset_SECTION_HEADER_three = offset_SECTION_HEADER_two+40
        Name_one = s[offset_SECTION_HEADER:offset_SECTION_HEADER+8]
        fp.seek(offset_SECTION_HEADER+8+4)
        VirtualAddress_one = byte2int(little_endian(fp.read(4)))
        PointerToRawData_one = byte2int(little_endian(fp.read(8)[4:]))
        Name_two = s[offset_SECTION_HEADER_two:offset_SECTION_HEADER_two+8]
        fp.seek(offset_SECTION_HEADER_two+8+4)
        VirtualAddress_two = byte2int(little_endian(fp.read(4)))
        PointerToRawData_two = byte2int(little_endian(fp.read(8)[4:]))
        Name_three = s[offset_SECTION_HEADER_three:offset_SECTION_HEADER_three+8]
        fp.seek(offset_SECTION_HEADER_three+8+4)
        VirtualAddress_three = byte2int(little_endian(fp.read(4)))
        PointerToRawData_three = byte2int(little_endian(fp.read(8)[4:]))


def analysis_IAT():
    pass

def analysis_EAT():
    pass     
        






def main():
    splitToSections()

if __name__ == '__main__':
    main()
    print('address of NT',hex(offset_NT))
    print('address of IMAGE_OPTIONAL_HEADER',hex(offset_OPTIONAL_HEADER))
    print('address of Section Header',hex(offset_SECTION_HEADER))
    print('section one:')
    print('section name:',Name_one,'section rva:',hex(VirtualAddress_one),'section raw:',hex(PointerToRawData_one))
    print('section two')
    print('section name:',Name_two,'section rva:',hex(VirtualAddress_two),'section raw:',hex(PointerToRawData_two))
    print('section three')
    print('section name:',Name_three,'section rva:',hex(VirtualAddress_three),'section raw:',hex(PointerToRawData_three))
    '''
    print('test rva2raw:')
    print('rva:0x5000','raw:',hex(rva2raw(b'\x50\x00')))
    print('rva:0x13314','raw:',hex(rva2raw(b'\x01\x33\x14')))
    '''
