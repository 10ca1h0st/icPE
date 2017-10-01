#!/usr/bin/python3
#-*- coding:utf-8 -*-
'''
一个查看dll文件的pe结构的工具
'''

import sys
from itertools import count

filename = sys.argv[1]

'''
除了代表地址的字段要用10进制保存，其他都用bytes保存，即b'\x00'这种形式
因为文件在磁盘时的PE头的地址与在内存时一样，所以PE头中的所有offset类变量不用进行rva2raw
但是，因为文件在磁盘时的用NULL字节填充的长度与在内存时不一样，所以，PE体中的offset类变量需要进行rva2raw
所以对于这种变量，定义两种形式，一种存放rva，另一种存放raw
例如：offset_IMPORT_DESCRIPTOR和offset_IMPORT_DESCRIPTOR_raw
'''

names = globals()

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
offset_DataDirectory = 0
DataDirectory = []
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
#IMAGE_IMPORT_DESCRIPTOR
offset_IMPORT_DESCRIPTOR = 0
offset_IMPORT_DESCRIPTOR_raw = 0
OriginalFirstThunk = 0
OriginalFirstThunk_raw = 0
Name_in_IMPORT_DESCRIPTOR = 0
Name_in_IMPORT_DESCRIPTOR_raw = 0
FirstThunk = 0
FirstThunk_raw = 0
end_IMPORT_DESCRIPTOR = b'\x00'*20

dll_names_IAT = []

dll_function_name_IAT = {}




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
    global offset_NT,offset_OPTIONAL_HEADER,NumberOfRvaAndSizes,offset_SECTION_HEADER,offset_DataDirectory,\
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
        offset_DataDirectory = offset_OPTIONAL_HEADER+96
        #print('address of datadirectory:',hex(offset_DataDirectory))
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
    global offset_DataDirectory,NumberOfRvaAndSizes,DataDirectory,\
    offset_IMPORT_DESCRIPTOR_raw,OriginalFirstThunk_raw,Name_in_IMPORT_DESCRIPTOR_raw,FirstThunk_raw,\
    offset_IMPORT_DESCRIPTOR,OriginalFirstThunk,Name_in_IMPORT_DESCRIPTOR,FirstThunk,end_IMPORT_DESCRIPTOR,\
    dll_names_IAT,names,dll_function_name_IAT
    length = byte2int(NumberOfRvaAndSizes)
    DataDirectory = [{} for i in range(length)]
    with open(filename,'rb') as fp:
        s = fp.read()
        for i in range(length):
            DataDirectory[i]['rva'] = byte2int(little_endian(s[offset_DataDirectory+i*8:offset_DataDirectory+(i+1)*8][:4]))
            DataDirectory[i]['size'] = little_endian(s[offset_DataDirectory+i*8:offset_DataDirectory+(i+1)*8][4:])
            #print(hex(DataDirectory[i]['rva']))
            #print(DataDirectory[i]['size'])
        offset_IMPORT_DESCRIPTOR = DataDirectory[1]['rva']
        offset_IMPORT_DESCRIPTOR_raw = rva2raw(offset_IMPORT_DESCRIPTOR)
        OriginalFirstThunk = byte2int(little_endian(s[offset_IMPORT_DESCRIPTOR_raw:offset_IMPORT_DESCRIPTOR_raw+4]))
        OriginalFirstThunk_raw = rva2raw(OriginalFirstThunk)
        Name_in_IMPORT_DESCRIPTOR = byte2int(little_endian(s[offset_IMPORT_DESCRIPTOR_raw+12:offset_IMPORT_DESCRIPTOR_raw+16]))
        Name_in_IMPORT_DESCRIPTOR_raw = rva2raw(Name_in_IMPORT_DESCRIPTOR)
        FirstThunk = byte2int(little_endian(s[offset_IMPORT_DESCRIPTOR_raw+16:offset_IMPORT_DESCRIPTOR_raw+20]))
        FirstThunk_raw = rva2raw(FirstThunk)
        fp.seek(offset_IMPORT_DESCRIPTOR_raw+20)

        '''
        为了统一变量名称
        '''
        names['Name_in_IMPORT_DESCRIPTOR_1'] = Name_in_IMPORT_DESCRIPTOR
        names['Name_in_IMPORT_DESCRIPTOR_raw_1'] = Name_in_IMPORT_DESCRIPTOR_raw
        names['OriginalFirstThunk_1'] = OriginalFirstThunk
        names['OriginalFirstThunk_raw_1'] = OriginalFirstThunk_raw
        names['FirstThunk_1'] = FirstThunk
        names['FirstThunk_raw_1'] = FirstThunk_raw
        for i in count(2):
            struct = fp.read(20)
            if struct == end_IMPORT_DESCRIPTOR:
                break
            names['OriginalFirstThunk_%s'%i] = byte2int(little_endian(struct[:4]))
            names['OriginalFirstThunk_raw_%s'%i] = rva2raw(names['OriginalFirstThunk_%s'%i])
            names['Name_in_IMPORT_DESCRIPTOR_%s'%i] = byte2int(little_endian(struct[12:16]))
            names['Name_in_IMPORT_DESCRIPTOR_raw_%s'%i] = rva2raw(names['Name_in_IMPORT_DESCRIPTOR_%s'%i])
            names['FirstThunk_%s'%i] = byte2int(little_endian(struct[16:]))
            names['FirstThunk_raw_%s'%i] = rva2raw(names['FirstThunk_%s'%i])

        #print('one:',hex(Name_in_IMPORT_DESCRIPTOR))
        #print('two:',hex(Name_in_IMPORT_DESCRIPTOR_2))
        #print('three:',hex(Name_in_IMPORT_DESCRIPTOR_3))
        #print(filename,' use %s dlls' %i)

        '''
        开始统计导入的dll文件名
        '''
        dll_names_IAT = ['' for j in range(i-1)]

        for i in range(1,len(dll_names_IAT)+1):
            k = 0
            for j in iter(s[names['Name_in_IMPORT_DESCRIPTOR_raw_%s'%i]:]):
                if j == 0:
                    break
                k = k+1
            dll_names_IAT[i-1] = str(s[names['Name_in_IMPORT_DESCRIPTOR_raw_%s'%i]:names['Name_in_IMPORT_DESCRIPTOR_raw_%s'%i]+k],'utf-8')

        '''
        开始找出每一的导入的dll文件里面的函数
        '''

        for i in range(len(dll_names_IAT)):
            address = []
            dll_function_name_IAT[dll_names_IAT[i]] = []
            fp.seek(names['OriginalFirstThunk_raw_%s'%(i+1)])
            while True:
                struct = fp.read(4)
                if struct == b'\x00\x00\x00\x00':
                    break
                address.append(rva2raw(little_endian(struct)))
            for j in range(len(address)):
                fp.seek(address[j]+2)
                k = 0
                while True:
                    struct = fp.read(1)
                    if struct == b'\x00':
                        break
                    k = k+1
                dll_function_name_IAT[dll_names_IAT[i]].append(str(s[address[j]+2:address[j]+2+k],'utf-8'))


                



def analysis_EAT():
    pass   
        






def main():
    splitToSections()
    analysis_IAT()
    analysis_EAT()

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
    #print(DataDirectory)
    print('address of IMAGE_IMPORT_DESCRIPTOR(raw):',hex(offset_IMPORT_DESCRIPTOR_raw))
    print('dll names',dll_names_IAT)
    for k,v in dll_function_name_IAT.items():
        print(k)
        print(v)
