import sys
import cfg
from read_files import *
from vulnerability import Vuln
from taint import *
from process import process_assign, process_calls, processing
from collections.abc import Sequence


'''def p_assign(assign, key):
    if(isinstance(assign, Taintdness)):
        return taint_taintdness(assign, key)
    
    elif((isinstance(assign, Sequence) and not isinstance(assign, (str, bytes, bytearray)) or isinstance(assign, set)) or isinstance(assign, dict)):
        return taint_collections(assign, key)
    
    elif(isinstance(assign,str)):
        return taint_var(assign, key)



def taint_taintdness(assign, key):
    if(len(assign.get_sinks()) != 0):
        if(assign.get_taint()):
            found_vulns.append(vuln_found(assign, vulns))
        else:
            var_name = assign.get_param()
            if(var_name in var):
                var_taint = var[var_name]
                if(var_taint.get_taint()):
                    var_taint.set_sinks(assign.get_sink())
                    found_vulns.append(vuln_found(var_taint, vulns))
        var[key] = assign
        return assign
    elif(len(assign.get_sanitizers()) != 0):
        if(key in var):
            var_taint = var[key]
            var_taint.set_sanitizers(assign.get_sanitizers())
        else:
            var_taint = assign
        var[key] = var_taint
        return var_taint
    else:
        var[key] = assign
        return assign


def taint_collections(assign, key):
    if(isinstance(assign, list) or isinstance(assign, tuple)):
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
        var[key] = Taintdness(False, [], [], [], [])
        return var[key]'''
    
def p_code(program):
    for instruction in program:
        if instruction['ast_type'] == 'Assign':
            dicti = process_assign(instruction)
            cfg.processed = {**cfg.processed, **dicti}
        elif instruction['ast_type'] == 'Expr': #para por exemplo se chama apenas uma funcao com um argumento, que nao tem retorno---exemplo: clean(a)
            process_calls(instruction, processing(instruction['value']))

        elif instruction['ast_type'] == 'FunctionDef': #quando se define o corpo duma funçao
            p_code(instruction['body'])
        
        elif instruction['ast_type'] == 'While' or instruction['ast_type'] == 'For':
            for i in range(10):
                dictif =  p_code(instruction['body'])
                #differs if runned twice???
                dictif =  p_code(instruction['body'])
                cfg.processed = {**cfg.processed, **dictif}
        elif instruction['ast_type'] == 'If':
            dictif1 =  p_code(instruction['body'])
            cfg.processed = {**cfg.processed, **dictif1}
            if 'orelse' in instruction:
                dictif2 =  p_code(instruction['orelse'])
                cfg.processed = {**cfg.processed, **dictif2}
                for el in dictif1:
                    if el in dictif2:
                        var_taint2 = dictif2[el]
                        var_taint1 = dictif1[el]
                        if var_taint2.get_taint() != var_taint1.get_taint():
                            if var_taint2.get_taint():
                                cfg.processed[el] = var_taint2
                            else:
                                cfg.processed[el] = var_taint1
                        elif var_taint2.get_taint() and var_taint1.get_taint():
                            cfg.processed[el].add_vulns(var_taint1.get_vulns())
                            cfg.processed[el].add_sources(var_taint1.get_sources())
                            cfg.processed[el].add_sanitizers(var_taint1.get_sanitizers())
                            cfg.processed[el].add_sinks(var_taint1.get_sinks())


    return cfg.processed
                
if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Please provide the program to be analyzed and the patterns")
        exit(0)

    program_file = sys.argv[1]
    pattern_file = sys.argv[2] 
    cfg.init_global_variables(pattern_file)

    program = read_program(program_file)
    p_code(program)

    print(cfg.processed)

    write_output(program_file, cfg.found_vulns)
    
    #Augassign - a += 2
            
        
                
