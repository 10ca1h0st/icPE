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
VirtualSize_one = b'\x00\x00\x00\x00'
VirtualAddress_one = 0
SizeOfRawData_one = b'\x00\x00\x00\x00'
PointerToRawData_one = 0
Characteristics_one_in_SECTION_HEADER = b'\x00\x00\x00\x00'
    #第二个节区头
VirtualSize_two = b'\x00\x00\x00\x00'
VirtualAddress_two = 0
SizeOfRawData_two = b'\x00\x00\x00\x00'
PointerToRawData_two = 0
Characteristics_two_in_SECTION_HEADER = b'\x00\x00\x00\x00'
    #第三个节区头
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

def main():
    splitToSections()



def splitToSections():
    global offset_NT,offset_OPTIONAL_HEADER,NumberOfRvaAndSizes,offset_SECTION_HEADER
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
        








if __name__ == '__main__':
    main()
    print('address of NT',hex(offset_NT))
    print('address of IMAGE_OPTIONAL_HEADER',hex(offset_OPTIONAL_HEADER))
    print('address of Section Header',hex(offset_SECTION_HEADER))