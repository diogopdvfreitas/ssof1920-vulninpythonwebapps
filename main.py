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
    
    elif(isinstance(assign, Sequence) and not isinstance(assign, (str, bytes, bytearray))):
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
    if(isinstance(assign, list)):
        v_taint = []
        for l in assign:
            v_taint.append(p_assign(l, key))
        var[key] = v_taint
        return v_taint
    elif(isinstance(assign, tuple)):
        v_taint = ()
        for t in assign:
            v_taint = v_taint + (p_assign(t, key),)
        var[key] = v_taint
        return v_taint
    elif(isinstance(assign, set)):
        v_taint = {p_assign(assign[0], key)}
        for i in range(1, len(assign)):
            v_taint.add()(p_assign(assign[i], key))
        var[key] = v_taint
        return v_taint
    elif(isinstance(assign, dict)):
        v_taint = {}
        for k in assign:
            v_taint[k] = p_assign(v_taint[k], key)
        return v_taint

def taint_var(assign, key):
    if assign in var:
        var[key] = var[assign]
        return var[assign]
    else:
        var[key] = Taintdness(False, "", "", "", "")
        return var[key]


if len(sys.argv) != 3:
    print("Please provide the program to be analyzed and the patterns")
    exit(0)

pattern_file = sys.argv[2] 
vulns = read_patterns(pattern_file)

program_file = sys.argv[1]
program = read_program(program_file)


user_func = []
var = {}
found_vulns = []
processed = {}

for instruction in program:
    
    if instruction['ast_type'] == 'Assign':
        dicti = process_assign(instruction, vulns, user_func, processed)
        processed = {**processed, **dicti}
        
        for key in processed:
            assign = processed[key]
            p_assign(assign, key)
        print(var)
        
    elif instruction['ast_type'] == 'Expr': #para por exemplo se chama apenas uma funcao com um argumento, que nao tem retorno---exemplo: clean(a)
        process_calls(instruction, processing(instruction['func']), processed)
                
    elif instruction['ast_type'] == 'FunctionDef': #quando se define o corpo duma funçao
        for instruction_func in instruction['body']:
            if instruction_func['ast_type'] == 'Assign': 
                dictf = process_assign(instruction_func, vulns, user_func, processed)
                processed = {**processed, **dictf}
            
                for key in processed:
                    assign = processed[key]
                    p_assign(assign, key)
                print(var)
            
            elif instruction_func['ast_type'] == 'Expr': 
                process_calls(instruction_func, processing(instruction_func['func']), processed)      
        
    #Augassign - a += 2
            
        
                
