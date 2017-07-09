#-*- coding: utf-8 -*-

from idautils import *
from idaapi import *
from idc import *
import re
import sys

block_stack_str_intro = ["lea ecx, [esp+4]","and esp, 0FFFFFFF0h","push dword ptr [ecx-4]","push ebp","mov ebp, esp","push ecx","mov eax, large gs:14h"]
block_stack_str_outro = ["call ___stack_chk_fail","leave","lea esp, [ecx-4]","lea esp, [ecx-4]","retn","mov ecx, [ebp+var_4]"]


class Decompile:
    def __init__(self, assembly_list):
        self.assembly_command = assembly_list
        self.c_code = [] # 디컴파일된 C코드를 라인별로 저장할 리스트입니다.
        self.user_function =[] # 코드에서 호출되는 함수정보를 따로 저장합니다. 함수 명이 _로 시작되는 것과 아닌 것으로 구분하여 사용자 정의 함수인지 구분 가능함.
        self.library_function =[]        
    
    
    def make_shape_of_main(self): # 디컴파일 작업 맨 마지막 부분에 할 것
        loop_cnt = len(self.assembly_command)
        ret_some = re.compile('mov eax, d*')
        while loop_cnt: # return value를 찾기 위한 작업입니다. 종료시점에 eax 값을 찾아내기 위해 거꾸로 올라갑니다.
            if ret_some.match(self.assembly_command[loop_cnt-1]):
                self.c_code.append("return" + self.assembly_command[loop_cnt-1].split(",")[1] + ";") 
                break
            loop_cnt -= 1
            
        self.c_code.insert(0, "int main(int argc, char* argv[]){")        
        self.c_code.append("}")
        
    def decom_call(self):
        call_lib = re.compile('call _.*')
        call_user = re.compile('call ^_.*')
        index = 0
        push_search_cnt = 0
        for command in self.assembly_command:
            
            if call_lib.match(command):
                
                function_name = command.replace("call", "").strip()
                self.library_function.append(function_name)  
                
                push_arg = re.compile('push .*')
                arg_list = []
                push_search_cnt = index-1
                while push_arg.match(self.assembly_command[push_search_cnt]): # call 명령어부터 거꾸로 올라가면서 push된 값들을 찾습니다.                  
                    argument = self.assembly_command[push_search_cnt].replace("push", "").strip()
                    arg_list.append(argument)
                    push_search_cnt -= 1               
                
                self.c_code.append(function_name + str(arg_list).replace("[","(").replace("]",")"))
            if call_user.match(command):
                function_name = command.replace("call", "").strip()
                self.user_function.append(function_name) ## 함수정보를 따로 저장해야 user function 내부 디컴파일을 추가로 할 수 있습니다.
                
                push_arg = re.compile('push .*')
                arg_list = []
                push_search_cnt = index-1
                while push_arg.match(self.assembly_command[push_search_cnt]): # call 명령어부터 거꾸로 올라가면서 push된 값들을 찾습니다.
                    argument = self.assembly_command[push_search_cnt].replace("push", "").strip()
                    arg_list.append(argument)
                    push_search_cnt -= 1               
                
                self.c_code.append(function_name + str(arg_list).replace("[","(").replace("]",")"))
                
            index += 1        




def delete_stack(asm):
    global block_stack_str_intro
    global block_stack_str_outro

    for item in block_stack_str_intro: # intro부분의 스택포인터를 찾아서 제거합니다
        for num in range(len(asm)):
            if len(asm)-1 <= num:
                break
            if asm[num] == item:
                asm.pop(num)
                num=num-1
    for item in block_stack_str_outro: # outro 부분의 스택포인터를 찾아서 제거합니다
        for num in range(len(asm)):
            if len(asm) <= num:
                break
            if asm[num] == item:
                asm.pop(num)
                num=num-1

    sub_esp=re.compile('sub esp, \d*') # [sub esp, <number>] 를 찾는 정규식 저 형태이면 match 가 리턴 아니면 None 리턴
    add_esp=re.compile('add esp, \d*') # [add esp, <number>] 를 찾는 정규식 저 형태이면 match 가 리턴 아니면 None 리턴

    for num in range(len(asm)):   
        if len(asm) <= num:
            break
        if add_esp.match(asm[num]): # [sub esp, <number>] 형태이면 match를 받아서 제거
            asm.pop(num)
            num=num-1
        if sub_esp.match(asm[num]): # [add esp, <number>] 형태이면 match를 받아서 제거
            asm.pop(num)
            num=num-1
    return asm

def check_var(asm):
    global variable_cnt
    if asm.find("[ebp+var") >= 0:
        var_str = 'v'+str(variable_cnt)
        variable_cnt += 1
        return var_str
    else:
        return asm

def delete_coma(asm):
    return asm.replace(',',"")

### 초기화와 사전작업
print "############run#############"
var_str = ""
patt = re.compile("[^\t]+")
variable_cnt = 0

main_instruct = []
my_instruct_list = []
###



ea = BeginEA() # Binary 부분을 받아옵니다.
list_cnt = 0
for funcea in Functions(SegStart(ea), SegEnd(ea)): # section 주소를 받아옵니다.
    functionName = GetFunctionName(funcea) # 해당 함수의 이름을 받아옵니다.
    if functionName == 'main':
        for (startea, endea) in Chunks(funcea): # 함수의 시작주소와 끝나는 주소를 알아옵니다.
            for head in Heads(startea, endea): 
                main_instruct.append(GetDisasm(head)) # ASM instruction을 받아옵니다.
                my_instruct_list.append(main_instruct[list_cnt].split())
                list_cnt += 1
asm_str = ""

for i in range(0,len(my_instruct_list)):
    asm_str += ' '.join(my_instruct_list[i]) + '\n'

asm_str = asm_str.split("\n") # '\n' 을 기준으로 잘라 리스트를 생성합니다.

asm_str = delete_stack(asm_str) # 스택프레임을 제거합니다.

##### 여기까지 오면 스택프레임을 제외하고 디컴파일에 필요한 어셈블리 코드 리스트가 asm_str에 들어가게 되었습니다. 


decompiled_info = Decompile(asm_str)

'''
디컴파일 내용 부분
'''
decompiled_info.decom_call() # 함수 call 디컴파일
'''
디컴파일 내용 부분
'''
decompiled_info.make_shape_of_main() #

for code_line in decompiled_info.c_code: # 한줄 한줄 출력하는 부분
