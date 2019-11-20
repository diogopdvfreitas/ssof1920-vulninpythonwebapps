import sys
from read_files import read_patterns
from read_files import read_program
from vulnerability import Vuln
from process import process_assign


if(len(sys.argv) != 3):
    print("Please provide the program to be analyzed and the patterns")
    exit(0)

pattern_file = sys.argv[2]
vulns = read_patterns(pattern_file)

program_file = sys.argv[1]
program = read_program(program_file)


for instruction in program:
    if(instruction['ast_type'] == 'Assign'):
        process_assign(instruction)
            
        
                
