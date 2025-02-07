import sys
import json
import os
from vulnerability import Vuln
import json

'''Read patterns file, creates object with information about vulnerabilities (sources, sanitization methods and sinks) 
and stores in a list. '''
def read_patterns(pattern_file):
    if os.path.exists(pattern_file):
        with open(pattern_file) as json_file:
            patterns = json.load(json_file)
    else:
        print("Patterns file: " + pattern_file + " doesn't exist")
        sys.exit(1)

    vulns = []
    for pattern in patterns:
        vuln_name = pattern['vulnerability']
        vuln_exists = False
        for vuln in vulns:
            if(vuln_name == vuln.get_vulnerability()):
                vuln.add_sources(pattern['sources'])
                vuln.add_sanitizers(pattern['sanitizers'])
                vuln.add_sinks(pattern['sinks'])
                vuln_exists = True
                break
        if(not vuln_exists):    
            vuln_obj = Vuln(pattern['vulnerability'], pattern['sources'], pattern['sanitizers'], pattern['sinks'])
            vulns.append(vuln_obj)
    return vulns

'''Read program file and returns the body'''
def read_program(program_file):
    if os.path.exists(program_file):
        with open(program_file, encoding='utf-8') as json_file:
            program = json.load(json_file)
    else:
        print("Patterns file: " + program_file + " doesn't exist")
        sys.exit(1)
    return program['body']

def write_output(program_file, found_vulns):
    process_program = program_file.split(".")
    file_name = process_program[0]
    p_output = file_name + '.output.json'
    j = json.dumps(found_vulns)
    '''with open(p_output, 'w') as f:
        f.write('[')
        for item in found_vulns:
            f.write("%s\n" % item)
        f.write(']')'''
    f = open(p_output, 'w')
    f.write(j)
    f.close()