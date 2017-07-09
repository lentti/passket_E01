from idautils import *
from idaapi import *
from idc import *
import re
import sys

block_stack_str_intro = ["lea ecx, [esp+4]","and esp, 0FFFFFFF0h","push dword ptr [ecx-4]","push ebp","mov ebp, esp","push ecx","mov eax, large gs:14h"]
block_stack_str_outro = ["call ___stack_chk_fail","leave","lea esp, [ecx-4]","lea esp, [ecx-4]","retn","mov ecx, [ebp+var_4]"]
  

print "############run#############"
var_str = ""

class magicstring(str):
  magicsplit = str.split

patt = re.compile("[^\t]+")
variable_cnt = 0

def delete_stack(asm):
  global block_stack_str_intro
  global block_stack_str_outro

  for item in block_stack_str_intro: # deleting intro
    for num in range(len(asm)):
      if len(asm)-1 <= num:
        break
      if asm[num] == item:
        asm.pop(num)
        num=num-1
  for item in block_stack_str_outro: # deleting outro
    for num in range(len(asm)):
      if len(asm) <= num:
        break
      if asm[num] == item:
        asm.pop(num)
        num=num-1

  sub_esp=re.compile('sub esp, \d*') # to remove [sub esp, <number>]
  add_esp=re.compile('add esp, \d*') # to remove [add esp, <number>]

  for num in range(len(asm)):   
    if len(asm) <= num:
      break
    if add_esp.match(asm[num]):
      asm.pop(num)
      num=num-1
    if sub_esp.match(asm[num]):
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

main_instruct = []
my_instruct_list = []

ea = BeginEA() #get binary section
list_cnt = 0
for funcea in Functions(SegStart(ea), SegEnd(ea)): #get section address
    functionName = GetFunctionName(funcea) #get function name of address
    if functionName == 'main':
       for (startea, endea) in Chunks(funcea): #get start,end address of function
                 for head in Heads(startea, endea): 
                   main_instruct.append(GetDisasm(head))#get asm instruction.
                   a = magicstring(main_instruct[list_cnt])
                   my_instruct_list.append(a.magicsplit())
                   list_cnt += 1
asm_str = ""
for i in range(0,len(my_instruct_list)):
    asm_str += ' '.join(my_instruct_list[i]) + "\n"

asm_str = asm_str.split("\n") # split by line
asm_str = delete_stack(asm_str) # removing stack frame

# printing section
for item in asm_str:
  print item