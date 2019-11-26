import sys
from read_files import read_patterns
from read_files import read_program
from vulnerability import Vuln
from taint import Taintdness
from taint import vuln_found
from process import process_assign
from process import process_calls
from process import processing
from collections.abc import Sequence


def p_assign(assign, key):
    if(isinstance(assign, Taintdness)):
        return taint_taintdness(assign, key)
    
    elif((isinstance(assign, Sequence) and not isinstance(assign, (str, bytes, bytearray)) or isinstance(assign, set)) or isinstance(assign, dict)):
        return taint_collections(assign, key)
    
    elif(isinstance(assign,str)):
        return taint_var(assign, key)



def taint_taintdness(assign, key):
    if(len(assign.get_sink()) != 0):
        if(assign.get_taint()):
            found_vulns.append(vuln_found(assign, vulns))
        else:
            var_name = assign.get_param()
            if(var_name in var):
                var_taint = var[var_name]
                if(var_taint.get_taint()):
                    var_taint.set_sink(assign.get_sink())
                    found_vulns.append(vuln_found(var_taint, vulns))
        var[key] = assign
        return assign
    elif(len(assign.get_sanitizers()) != 0):
        if(key in var):
            var_taint = var[key]
            var_taint.set_sanitizer(assign.get_sanitizer())
        else:
            var_taint = assign
        var[key] = var_taint
        return var_taint
    else:
        var[key] = assign
        return assign


def taint_collections(assign, key):
    if(isinstance(assign, list) or isinstance(assign, tuple)):
        '''#v_taint = []
        for i in range(0,len(assign)):
            k = key + '[' + str(i) + ']'
            aux = p_assign(assign[i], k)
            if(aux != None):
                var[k] = aux
            #v_taint.append(var[k])
        #return v_taint'''
        for i in range(0,len(assign)):
            k = key + '[' + str(i) + ']'
            aux = p_assign(assign[i], k)
            if(aux != None):
                var[k] = aux
    elif(isinstance(assign, set)):
        for i in range(0, len(assign)):
            el = assign.pop()
            k = key + '[' + str(i) + ']'
            aux = p_assign(el, k)
            if(aux != None):
                var[k] = aux
    elif(isinstance(assign, dict)):
        for k in assign:
            ky = key + '[\"' + k + '\"]'
            if(isinstance(assign[k], Taintdness)):
                var[ky] = assign[k]
            else:
                aux = p_assign(assign[k], ky)
                if(aux != None):
                     var[ky] = aux

def taint_var(assign, key):
    if assign in var:
        var[key] = var[assign]
        return var[assign]
    else:
        var[key] = Taintdness(False, "", "", "", "")
        return var[key]
    
def p_code(program, vulns, processed):
    for instruction in program:
        if instruction['ast_type'] == 'Assign':
            dicti = process_assign(instruction, vulns, processed)
            processed = {**processed, **dicti}
            for key in processed:
                assign = processed[key]
                p_assign(assign, key)
        elif instruction['ast_type'] == 'Expr': #para por exemplo se chama apenas uma funcao com um argumento, que nao tem retorno---exemplo: clean(a)
            process_calls(instruction, processing(instruction['value'], processed), processed)
                    
        elif instruction['ast_type'] == 'FunctionDef': #quando se define o corpo duma funçao
            p_code(instruction['body'], vulns, processed)
        
        elif instruction['ast_type'] == 'While' or instruction['ast_type'] == 'For':
            dictif =  p_code(instruction['body'], vulns, processed)
            processed = {**processed, **dictif}
        elif instruction['ast_type'] == 'If':
            dictif =  p_code(instruction['body'], vulns, processed)
            processed = {**processed, **dictif}
            dictif =  p_code(instruction['orelse'], vulns, processed)
            processed = {**processed, **dictif}
            
    return processed


if len(sys.argv) != 3:
    print("Please provide the program to be analyzed and the patterns")
    exit(0)

pattern_file = sys.argv[2] 
vulns = read_patterns(pattern_file)

program_file = sys.argv[1]
program = read_program(program_file)
var = {}
found_vulns = []
processed = p_code(program, vulns, {})
print(processed)


        
    #Augassign - a += 2
            
        
                
