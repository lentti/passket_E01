#-*- coding: utf-8 -*-
from idautils import *
from idaapi import *
from idc import *
import re
import sys




def delete_stack(asm): # 스택프레임 제거 함수
    stackFrameIntro=re.compile('mov eax, large gs:[a-z0-9]*')
    stackFrameOutro=re.compile('xor edx, large gs:[a-z0-9]*')
    for i in range(len(asm)):
        if stackFrameIntro.match(asm[i]):
            for j in range(i+1):
                asm.pop(0)
            break
    for i in range(len(asm)):
        if stackFrameOutro.match(asm[i]):
            for j in range(i, len(asm)):
                asm.pop(i)
            break
    subESP=re.compile('sub esp, \d*') # [sub esp, <number>] 를 찾는 정규식 저 형태이면 match 가 리턴 아니면 None 리턴
    addESP=re.compile('add esp, \d*') # [add esp, <number>] 를 찾는 정규식 저 형태이면 match 가 리턴 아니면 None 리턴

    for num in range(len(asm)):   
        if len(asm) <= num:
            break
        if addESP.match(asm[num]): # [sub esp, <number>] 형태이면 match를 받아서 제거
            asm.pop(num)
            num=num-1
        if subESP.match(asm[num]): # [add esp, <number>] 형태이면 match를 받아서 제거
            asm.pop(num)
            num=num-1

    return asm

####################이거 두개 함수 어디에 쓰는지 설명 추가바람
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
########################################################


############################# 디컴파일 클래스 
class Decompile:
    def __init__(self, assembly_list, assembly_dict, addr_list):
        self.assembly_dict = assembly_dict
        self.assembly_command = assembly_list
        self.addr_list = addr_list
        self.c_code = [] # 디컴파일된 C코드를 라인별로 저장할 리스트입니다.
        self.c_code_dict = {}
        self.user_function = [] # 코드에서 호출되는 함수정보를 따로 저장합니다. 함수 명이 _로 시작되는 것과 아닌 것으로 구분하여 사용자 정의 함수인지 구분 가능함.
        self.library_function = []
        self.variable = []
        self.variable_init_instruction = []
        self.calc_dict = {"sub":"-","add":"+","and":"&","or":"|","xor":"^","imul":"*"}

    def calc_loop(self,addr_list,param = [], var = {}):
        tmp = {}
        log = []
        for addr in addr_list:
            if len(param) > 0  and (len(param) > len(var)) :
                if GetOpnd(addr,1) == 'edi':
                    var[GetOpnd(addr,0)] = param[0]
                if GetOpnd(addr,1) == 'esi':
                    var[GetOpnd(addr,0)]  = param[1]
                if GetOpnd(addr,1) == 'edx':
                    var[GetOpnd(addr,0)]  = param[2]
            elif GetOpType(addr,0) == 1:
                
                if GetMnem(addr) == 'mov':
                    if GetOpType(addr,1) == 4: # mov reg, variable
                        tmp[GetOpnd(addr,0)] = var[GetOpnd(addr,1)]
                    if GetOpType(addr,1) == 1: # mov reg, reg
                        if GetOpnd(addr,1) in tmp:
                            tmp[GetOpnd(addr,0)] = tmp[GetOpnd(addr,1)]
                        elif GetOpnd(addr,1) in var:
                            tmp[GetOpnd(addr,0)] = var[GetOpnd(addr,1)]
                elif GetMnem(addr) in self.calc_dict:
                    if GetOpType(addr,1) == 4: # {calc} reg, variable
                        tmp[GetOpnd(addr,0)] = tmp[GetOpnd(addr,0)]+self.calc_dict[GetMnem(addr)]+var[GetOpnd(addr,1)]
                    if GetOpType(addr,1) == 1: # {calc} reg, reg
                        if GetOpnd(addr,1) in tmp:
                            tmp[GetOpnd(addr,0)] = tmp[GetOpnd(addr,0)]+self.calc_dict[GetMnem(addr)]+tmp[GetOpnd(addr,1)]
                        elif GetOpnd(addr,1) in var:
                            tmp[GetOpnd(addr,0)] = tmp[GetOpnd(addr,0)]+self.calc_dict[GetMnem(addr)]+var[GetOpnd(addr,1)]
                elif GetMnem(addr) == "lea":
                    if GetOpType(addr,1) == 4:
                        tmp[GetOpnd(addr,0)] = "&"+var[GetOpnd(addr,1)]
                    if GetOpType(addr,1) == 1: # {calc} reg, reg
                        if GetOpnd(addr,1) in tmp:
                            tmp[GetOpnd(addr,0)] = "&"+tmp[GetOpnd(addr,1)]
                        elif GetOpnd(addr,1) in var:
                            tmp[GetOpnd(addr,0)] = "&"+var[GetOpnd(addr,1)]
            elif GetOpType(addr,0) == 4: # variable
                if GetMnem(addr) == 'mov':
                    if GetOpType(addr,1) == 4: # mov variable, variable
                        var[GetOpnd(addr,0)] = var[GetOpnd(addr,1)]
                        log.append(GetOpnd(addr,0).replace("[ebp+","").replace("]","") + " = " + var[GetOpnd(addr,0)])
                        var[GetOpnd(addr,0)] = GetOpnd(addr,0).replace("[ebp+","").replace("]","")
                    if GetOpType(addr,1) == 1: # mov variable, reg
                        if GetOpnd(addr,1) in tmp:
                            var[GetOpnd(addr,0)] = tmp[GetOpnd(addr,1)]
                            log.append(GetOpnd(addr,0).replace("[ebp+","").replace("]","") + " = " + var[GetOpnd(addr,0)])
                            var[GetOpnd(addr,0)] = GetOpnd(addr,0).replace("[ebp+","").replace("]","")
                        elif GetOpnd(addr,1) in var:
                            var[GetOpnd(addr,0)] = var[GetOpnd(addr,1)]
                            log.append(GetOpnd(addr,0).replace("[ebp+","").replace("]","") + " = " + var[GetOpnd(addr,0)])
                            var[GetOpnd(addr,0)] = GetOpnd(addr,0).replace("[ebp+","").replace("]","")
                elif GetMnem(addr) in self.calc_dict:
                    if GetOpType(addr,1) == 4: # {calc} variable, variable
                        var[GetOpnd(addr,0)] = var[GetOpnd(addr,0)]+self.calc_dict[GetMnem(addr)]+var[GetOpnd(addr,1)]
                        log.append(GetOpnd(addr,0).replace("[ebp+","").replace("]","") + " = " + var[GetOpnd(addr,0)])
                        var[GetOpnd(addr,0)] = GetOpnd(addr,0).replace("[ebp+","").replace("]","")
                    if GetOpType(addr,1) == 1: # {calc} variable, reg
                        if GetOpnd(addr,1) in tmp:
                            var[GetOpnd(addr,0)] = var[GetOpnd(addr,0)]+self.calc_dict[GetMnem(addr)]+tmp[GetOpnd(addr,1)]
                            log.append(GetOpnd(addr,0).replace("[ebp+","").replace("]","") + " = " + var[GetOpnd(addr,0)])
                            var[GetOpnd(addr,0)] = GetOpnd(addr,0).replace("[ebp+","").replace("]","")
                        elif GetOpnd(addr,1) in var:
                            var[GetOpnd(addr,0)] = var[GetOpnd(addr,0)]+self.calc_dict[GetMnem(addr)]+var[GetOpnd(addr,1)]
                            log.append(GetOpnd(addr,0).replace("[ebp+","").replace("]","") + " = " + var[GetOpnd(addr,0)])
                            var[GetOpnd(addr,0)] = GetOpnd(addr,0).replace("[ebp+","").replace("]","")
                elif GetMnem(addr) == "lea":
                    if GetOpType(addr,1) == 4:
                        var[GetOpnd(addr,0)] = "&"+var[GetOpnd(addr,1)]
                        log.append(GetOpnd(addr,0).replace("[ebp+","").replace("]","") + " = " + var[GetOpnd(addr,0)])
                        var[GetOpnd(addr,0)] = GetOpnd(addr,0).replace("[ebp+","").replace("]","")
                    if GetOpType(addr,1) == 1: # {calc} reg, reg
                        if GetOpnd(addr,1) in tmp:
                            var[GetOpnd(addr,0)] = "&"+tmp[GetOpnd(addr,1)]
                            log.append(GetOpnd(addr,0).replace("[ebp+","").replace("]","") + " = " + var[GetOpnd(addr,0)])
                            var[GetOpnd(addr,0)] = GetOpnd(addr,0).replace("[ebp+","").replace("]","")
                        elif GetOpnd(addr,1) in var:
                            var[GetOpnd(addr,0)] = "&"+var[GetOpnd(addr,1)]
                            log.append(GetOpnd(addr,0).replace("[ebp+","").replace("]","") + " = " + var[GetOpnd(addr,0)])
                            var[GetOpnd(addr,0)] = GetOpnd(addr,0).replace("[ebp+","").replace("]","")

        return var,tmp,log

    def make_shape_of_main(self): # 디컴파일 작업 맨 마지막 부분에 할 것
        loop_cnt = len(self.addr_list)
        #ret_some = re.compile('mov eax, d*')
        cur_asm = self.addr_list[loop_cnt-1]
        while cur_asm != self.addr_list[0]: # return value를 찾기 위한 작업입니다. 종료시점에 eax 값을 찾아내기 위해 거꾸로 올라갑니다.
            #if ret_some.match(self.assembly_command[loop_cnt-1]):
            if GetMnem(cur_asm) == 'mov' and GetOpnd(cur_asm,0) == 'eax':
                #print GetDisasm(cur_asm)
                #self.c_code.append("return" + self.assembly_command[loop_cnt-1].split(",")[1] + ";") 
                self.c_code.append("return"+GetOpnd(cur_asm,1)+";")
                self.c_code_dict[cur_asm] = "return "+GetOpnd(cur_asm,1)+";"
                
                break
            #loop_cnt -= 1
            cur_asm = PrevHead(cur_asm)
        self.c_code.insert(0, "int main(int argc, char* argv[]){")        
        self.c_code.append("}")
        
        self.c_code_dict[addr_list[0]-1] = "int main(int argc, char* argv[]){"
        self.c_code_dict[addr_list[-1]+1] = "}"         

    def decom_call(self):
        call_lib = re.compile('[_.*]')
        call_user = re.compile('[^_.*]')
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
                    argument = GetOperandValue(cur_argv,0)
                    if argument == 0:
                        eax_search_cnt=push_search_cnt-1

                        while True:
                            eax_search_addr=self.addr_list[eax_search_cnt]

                            if (GetMnem(eax_search_addr)=="mov" or GetMnem(eax_search_addr)=="lea") and ("eax" in GetOpnd(eax_search_addr,0)):

                                if GetMnem(eax_search_addr)=="mov":
                                    argument=GetOpnd(eax_search_addr,1).replace("[ebp+","").replace("]","")
                                    #===========================================
                                    if "eax" in argument:
                                        call_search_cnt=eax_search_cnt

                                        while True:
                                            call_search_addr=self.addr_list[call_search_cnt]
                                            #print call_search_addr
                                            if GetMnem(call_search_addr)=="call":
                                                calc_addr=self.addr_list[call_search_cnt+1]
                                                break
                                            else:
                                                call_search_cnt=call_search_cnt-1
                                        #print GetMnem(calc_addr)

                                        top_search_cnt=eax_search_cnt
                                        while self.addr_list[top_search_cnt] > calc_addr:
                                            top_search_cnt-=1
                                        top_search_cnt+=1
                                        i=0
                                        candargs={}
                                        while GetMnem(top_search_cnt)!="push" and GetOpnd(self.addr_list[top_search_cnt],0)!="esp":
                                            if GetMnem(self.addr_list[top_search_cnt])=="mov":
                                                if GetOpnd(self.addr_list[top_search_cnt],0) in candargs:
                                                    if GetOpnd(self.addr_list[top_search_cnt],1) in candargs:
                                                        candargs[GetOpnd(self.addr_list[top_search_cnt],0)]=candargs[GetOpnd(self.addr_list[top_search_cnt],1)]
                                                    else:
                                                        if GetOpnd(self.addr_list[top_search_cnt],1)!="[eax]":
                                                            candargs[GetOpnd(self.addr_list[top_search_cnt],0)]=GetOpnd(self.addr_list[top_search_cnt],1)
                                                else:
                                                    if GetOpnd(self.addr_list[top_search_cnt],1) in candargs:
                                                        candargs.update({GetOpnd(self.addr_list[top_search_cnt],0):candargs[GetOpnd(self.addr_list[top_search_cnt],1)]})
                                                    else:
                                                        candargs.update({GetOpnd(self.addr_list[top_search_cnt],0):GetOpnd(self.addr_list[top_search_cnt],1)})

                                                #candargs.update({GetOpnd(self.addr_list[top_search_cnt],0):GetOpnd(self.addr_list[top_search_cnt],1).replace("[ebp+","").replace("]","")})
                                                    #eax=GetOpnd(self.addr_list[top_search_cnt],1).replace("[ebp+","").replace("]","")
                                                    #candargs.append(GetOpnd(self.addr_list[top_search_cnt],1).replace("[ebp+","").replace("]",""))
                                                        

                                                    
                                            elif GetMnem(self.addr_list[top_search_cnt])=="not":
                                                #if GetOpnd(self.addr_list[top_search_cnt],0) in candargs:
                                                candargs[GetOpnd(self.addr_list[top_search_cnt],0)]="~"+candargs[GetOpnd(self.addr_list[top_search_cnt],0)]
                                                    
                                                #else:
                                                 #   varargs="~"+varargs
                                            elif GetMnem(self.addr_list[top_search_cnt])=="lea":
                                                if GetOpnd(self.addr_list[top_search_cnt],0) in candargs:
                                                    if "[ebp" in GetOpnd(self.addr_list[top_search_cnt],1):
                                                        candargs[GetOpnd(self.addr_list[top_search_cnt],0)]=GetOpnd(self.addr_list[top_search_cnt],1).replace("[ebp+","").replace("]","")
                                                    else:
                                                        candargs[GetOpnd(self.addr_list[top_search_cnt],0)]=GetOpnd(self.addr_list[top_search_cnt],1)
                                                else:
                                                    lea_cre=GetOpnd(self.addr_list[top_search_cnt],1)[1:4]
                                                    fn_lea_op1=candargs[lea_cre].replace("var_","")
                                                    fn_lea_op2=GetOpnd(self.addr_list[top_search_cnt],1)[5:].replace("]","")
                                                    lea_ds=hex(int(fn_lea_op1,16)-int(fn_lea_op2,16)).replace("0x","")
                                                    #print fn_lea_op1
                                                    #print fn_lea_op2
                                                    candargs.update({GetOpnd(self.addr_list[top_search_cnt],0):"&[var_"+str(lea_ds)+"]"})
                                                    
                                                    #if GetOpnd(self.addr_list[top_search_cnt],1) in candargs:
                                                    #candargs.update({GetOpnd(self.addr_list[top_search_cnt],0):candargs[GetOpnd(self.addr_list[top_search_cnt],1)]})
                                                    #else:
                                                        #candargs.update({GetOpnd(self.addr_list[top_search_cnt],0):GetOpnd(self.addr_list[top_search_cnt],1)})

                                            elif GetMnem(self.addr_list[top_search_cnt])=="test":
                                                if GetOpnd(self.addr_list[top_search_cnt],0) in candargs:
                                                    if candargs[GetOpnd(self.addr_list[top_search_cnt],0)] == 0:
                                                        candargs["eax"]=str(1)
                                                        
                                                    else:
                                                        candargs["eax"]=str(0)
                                                        
                                                #top_search_cnt+=2
                                            elif GetMnem(self.addr_list[top_search_cnt])=="add":
                                                candargs[GetOpnd(self.addr_list[top_search_cnt],0)]+="+"+str(candargs[GetOpnd(self.addr_list[top_search_cnt],1)])

                                            elif GetMnem(self.addr_list[top_search_cnt])=="or":
                                                candargs[GetOpnd(self.addr_list[top_search_cnt],0)]+="||"+candargs[GetOpnd(self.addr_list[top_search_cnt],1)]
                                            elif GetMnem(self.addr_list[top_search_cnt])=="xor":
                                                candargs[GetOpnd(self.addr_list[top_search_cnt],0)]+="^"+candargs[GetOpnd(self.addr_list[top_search_cnt],1)]
                                            else:
                                                top_search_cnt+=1
                                            
                                            #print GetMnem(self.addr_list[top_search_cnt])
                                            top_search_cnt+=1
                                        #print candargs[eax]
                                        argument=candargs["eax"]

                                                #if GetOpnd(self.addr_list[top_search_cnt],0) in candargs:





                                elif GetMnem(eax_search_addr)=="lea":
                                    if GetMnem(self.addr_list[eax_search_cnt+1])=="add":
                                        lea_op1=GetOpnd(eax_search_addr,1).replace("[ebp+var_","").replace("]","")
                                        lea_op2=GetOpnd(self.addr_list[eax_search_cnt+1],1).replace("h","")
                                        eax_ds=int(lea_op1,16)-int(lea_op2,16)
                                        argument="&var_"+hex(eax_ds)
                                break;

                            else:
                                eax_search_cnt=eax_search_cnt-1

                # print argument[0]
                    if type(argument) == int or type(argument)==long:
                        if GetOpType(cur_argv,0) == 4:
                            arg_list.append(GetOpnd(cur_argv,0).replace("[ebp+","").replace("]",""))
                        else:
                            #print GetDisasm(cur_argv)
                            arg_list.append(GetString(argument))
                    else:
                        arg_list.append(argument)
                    #push_search_cnt -= 1               
                    cur_argv = PrevHead(cur_argv)
                parse = function_name+"("
                for argv in arg_list:
                    if argv.find('var') != -1:
                        parse += argv + ','
                    else:
                        parse += repr(argv)+','
                parse += ")"
                parse = parse.replace(',)',")")
                self.c_code.append(parse)
                self.c_code_dict[cur_argv] = parse

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
                self.c_code_dict[cur_argv] = function_name + str(arg_list).replace("[","(").replace("]",")")
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
        amount_of_var_init = 0
        pick = 0
        for var in self.variable:
            for asm_addr in self.addr_list:
                check = False
                if GetOpnd(asm_addr,0).find(var) != -1 :
                
                    if var_noninit.match(GetDisasm(asm_addr).split(",")[1].strip()): # 값을 넣긴 하지만 확정값이 아니라면 초기화만
                        self.variable_init_instruction.append(var+";")
                        self.c_code_dict[asm_addr] = var+";"
                        check = True
                        break
                    
                    if var_init.match(GetDisasm(asm_addr).split(",")[1].strip()): # 확정값을 넣는 부분을 찾으면 그 값으로 초기화하는 코드를 구현
                        value = GetDisasm(asm_addr).split(",")[1].strip()
                        self.variable_init_instruction.append(var+" = "+value+";")
                        self.c_code_dict[asm_addr] = var+" = "+value+";"
                        pick = asm_addr
                        check = True
                        break


            if check == False:  # 변수가 많은 경우에는 이런 구현이 문제가 될 수 있습니다.
                self.variable_init_instruction.append(var+";")
                self.assembly_dict[addr_list[0]+amount_of_var_init] = var+" = "+value+";"
                amount_of_var_init +=1
        addr_list_ = []
        pick2 = pick
        while GetMnem(pick) != 'sub' and GetOpnd(pick,0) != 'esp':
            addr_list_.append(pick)
            pick = NextHead(pick)
        var1 = {w.replace('var',"[ebp+var")+"]":w for w in self.variable}
        res,tmp,log = self.calc_loop(addr_list_,var=var1)
        for i in range(0,len(log)):
            self.variable_init_instruction.append(log[i])
        self.c_code += self.variable_init_instruction





########################실제로 기능을 하는 부분 ######### 클래스와 함수 선언 종료.

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
'''
for code_addr in sorted(decompiled_info.c_code_dict.keys()):
    print "%08x :"%code_addr, decompiled_info.c_code_dict[code_addr]
'''