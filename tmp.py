#-*- coding: utf-8 -*-

from idautils import *
from idaapi import *
from idc import *
import re
import sys
   
block_stack_str_intro = ["lea ecx, [esp+4]","and esp, 0FFFFFFF0h","push dword ptr [ecx-4]","push ebp","mov ebp, esp","push ecx","mov eax, large gs:14h"]
block_stack_str_outro = ["call ___stack_chk_fail","leave","lea esp, [ecx-4]","lea esp, [ecx-4]","retn","mov ecx, [ebp+var_4]"]

    
class Decompile:
  def __init__(self, assembly_list, assembly_dict, addr_list):
    self.assembly_dict = assembly_dict
    self.assembly_command = assembly_list
    self.addr_list = addr_list
    self.c_code = [] # 디컴파일된 C코드를 라인별로 저장할 리스트입니다.
    self.user_function = [] # 코드에서 호출되는 함수정보를 따로 저장합니다. 함수 명이 _로 시작되는 것과 아닌 것으로 구분하여 사용자 정의 함수인지 구분 가능함.
    self.library_function = []
    self.variable = []
    self.variable_init_instruction = []
  
  
  def make_shape_of_main(self): # 디컴파일 작업 맨 마지막 부분에 할 것
    loop_cnt = len(self.addr_list)
    #ret_some = re.compile('mov eax, d*')
    cur_asm = self.addr_list[loop_cnt-1]
    while cur_asm != self.addr_list[0]: # return value를 찾기 위한 작업입니다. 종료시점에 eax 값을 찾아내기 위해 거꾸로 올라갑니다.
      #if ret_some.match(self.assembly_command[loop_cnt-1]):
      if GetMnem(cur_asm) == 'mov' and GetOpnd(cur_asm,0) == 'eax':
        print GetDisasm(cur_asm)
        #self.c_code.append("return" + self.assembly_command[loop_cnt-1].split(",")[1] + ";") 
        self.c_code.append("return"+GetOpnd(cur_asm,1)+";")
        break
      #loop_cnt -= 1
      cur_asm = PrevHead(cur_asm)
    self.c_code.insert(0, "int main(int argc, char* argv[]){")        
    self.c_code.append("}")
      
  def decom_call(self):
    call_lib = re.compile('_.*')
    call_user = re.compile('^_.*')
    index = 0
    push_search_cnt = 0
    #for command in self.assembly_command:
    for command in self.addr_list:
      if GetMnem(command) == 'call' and call_lib.match(GetOpnd(command,0)):
        #function_name = command.replace("call", "").strip()
        function_name = GetOpnd(command,0)
        self.library_function.append(function_name)  
        #push_arg = re.compile('push .*')
        arg_list = []
        push_search_cnt = index-1
        cur_argv = self.addr_list[push_search_cnt]
        #while push_arg.match(self.assembly_command[push_search_cnt]): # call 명령어부터 거꾸로 올라가면서 push된 값들을 찾습니다.                  
        while GetMnem(cur_argv) == 'push':
          #argument = self.assembly_command[push_search_cnt].replace("push", "").strip()
          argument = GetOpnd(cur_argv,0)
          arg_list.append(argument)
          #push_search_cnt -= 1               
          cur_argv = PrevHead(cur_argv)
        self.c_code.append(function_name + str(arg_list).replace("[","(").replace("]",")"))
      
      if GetMnem(command) == 'call' and call_user.match(GetOpnd(command,0)):
        #function_name = command.replace("call", "").strip()
        function_name = GetOpnd(command,0)
        self.user_function.append(function_name) ## 함수정보를 따로 저장해야 user function 내부 디컴파일을 추가로 할 수 있습니다.  
        #push_arg = re.compile('push .*')
        arg_list = []
        push_search_cnt = index-1
        #while push_arg.match(self.assembly_command[push_search_cnt]): # call 명령어부터 거꾸로 올라가면서 push된 값들을 찾습니다.
        cur_argv = self.addr_list[push_search_cnt]
        while GetMnem(cur_argv) == 'push':
          #argument = self.assembly_command[push_search_cnt].replace("push", "").strip()
          argument = GetOpnd(cur_argv,0)
          arg_list.append(argument)
          #push_search_cnt -= 1               
          cur_argv = PrevHead(cur_argv)
        self.c_code.append(function_name + str(arg_list).replace("[","(").replace("]",")"))    
      index += 1
  
  
  def pop_variable_info(self): # 변수들만 뽑아내서 리스트에 저장합니다.
    for command in self.assembly_command:
      if "var" in command:
        index = command.find("var")
        self.variable.append(command[index:index+6].replace("]","").replace(",",""))
    
    self.variable = list(set(self.variable))
  
  def decom_variable_initialize(self): # 위에서부터 읽어서 변수에 확정값을 넣는 행위가 가장 먼저 나오면 그 값으로 초기화, 아닌 경우 그냥 초기화만
    # 디컴파일 작업 맨 처음 부분에 할 것, 변수 초기화 먼저 포함시킴
    self.pop_variable_info()
    var_init = re.compile("[0-9].*")
    var_noninit = re.compile("[^0-9].*")
    for var in self.variable:
      for command in self.assembly_command:
        check = False
        if command.find(var) != -1:
          
          if var_noninit.match(command.split(",")[1].strip()): # 값을 넣긴 하지만 확정값이 아니라면 초기화만
            self.variable_init_instruction.append(var+";")
            check = True
            break
          
          if var_init.match(command.split(",")[1].strip()): # 확정값을 넣는 부분을 찾으면 그 값으로 초기화하는 코드를 구현
            value = command.split(",")[1].strip()
            self.variable_init_instruction.append(var+" = "+value+";")
            check = True
            break
              
              
      if check == False:
        self.variable_init_instruction.append(var+";")

    self.c_code += self.variable_init_instruction        




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
addr_list=[]
addr_instruct_dict={}
asm_str = ""
###


ea = BeginEA() # Binary 부분을 받아옵니다.
list_cnt = 0
for funcea in Functions(SegStart(ea), SegEnd(ea)): # section 주소를 받아옵니다.
  functionName = GetFunctionName(funcea) # 해당 함수의 이름을 받아옵니다.
  if functionName == 'main':
      for (startea, endea) in Chunks(funcea): # 함수의 시작주소와 끝나는 주소를 알아옵니다.
          for head in Heads(startea, endea): 
              main_instruct.append(GetDisasm(head)) # ASM instruction을 받아옵니다.
              my_instruct_list.append(main_instruct[list_cnt].split()) # code내용을 긁어옵니다 (처리 필요)
              addr_list.append(head) # 주소를 addr_list에 저장합니다
              list_cnt += 1


for i in range(0,len(my_instruct_list)):
  asm_str += ' '.join(my_instruct_list[i]) + '\n' # code내용을 처리하여 다 합칩니다


asm_str = asm_str.split("\n") # '\n' 을 기준으로 잘라 리스트를 생성합니다.

for i in range(0,len(my_instruct_list)): # 
  addr_instruct_dict[addr_list[i]] = asm_str[i] # 코드 주소 : 코드 내용 을 가지는 딕셔너리를 생성합니다

asm_str = delete_stack(asm_str) # 스택프레임을 제거합니다.

##### 여기까지 오면 스택프레임을 제외하고 디컴파일에 필요한 어셈블리 코드 리스트가 asm_str에 들어가게 되었습니다. 

decompiled_info = Decompile(asm_str, addr_instruct_dict,addr_list)


decompiled_info.decom_variable_initialize() # 변수 초기화
'''
디컴파일 내용 부분
'''
decompiled_info.decom_call() # 함수 call 디컴파일
'''
디컴파일 내용 부분
'''
decompiled_info.make_shape_of_main() #

for code_line in decompiled_info.c_code: # 한줄 한줄 출력하는 부분
  print code_line
