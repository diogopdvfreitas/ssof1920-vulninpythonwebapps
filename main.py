import sys
from read_files import read_patterns
from read_files import read_program
from vulnerability import Vuln


if(len(sys.argv) != 3):
    print("Please provide the program to be analyzed and the patterns")
    exit(0)

pattern_file = sys.argv[2]
vulns = read_patterns(pattern_file)

program_file = sys.argv[1]
program = read_program(program_file)


for instruction in program:
    if(instruction['ast_type'] == 'Assign'):
        for target in instruction['targets']:
            var = []
            '''Name, tuple, Subscript (Que tenha descobrido)'''
            #Examplos para dictionary, tuples, etc
            if(target['ast_type'] == 'Name'):
                var.append(target['id'])
            elif(target['ast_type'] == 'Tuple'):
                for elt in target['elts']:
                    if(elt['ast_type'] == 'Name'):
                        var.append(elt['id'])
            #elif(target['ast_type'] == 'Subscript'):

        value = instruction['value']
        '''Tuple, Name, List'''
                
