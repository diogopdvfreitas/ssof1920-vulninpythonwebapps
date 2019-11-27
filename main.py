import sys
import cfg
from read_files import *
from vulnerability import Vuln
from taint import *
from process import process_assign, process_calls, processing
from collections.abc import Sequence

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