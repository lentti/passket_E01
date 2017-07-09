from idautils import *
from idaapi import *
from idc import *
import re
import sys

var_str = ""

class magicstring(str):
  magicsplit = str.split

patt = re.compile("[^\t]+")

def check_var(asm):
  global variable_cnt
  if asm.find("[ebp+var") >= 0:
      print variable_cnt
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

#parsing test. you don't have to see this
for i in range(0, len(my_instruct_list)):
  for j in range(0, len(my_instruct_list[i])):
      opcode = my_instruct_list[i][0]
      if opcode == 'mov'
        print my_instruct_list[i][1]
        dest = check_var(delete_coma(my_instruct_list[i][1]))
        sour = check_var(my_instruct_list[i][2])
        result_str = dest + " = " + sour + ";"
        print result_str
