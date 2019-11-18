import sys
import json
import os
from vulnerability import Vuln

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
            if(vuln_name == vuln.vulnerability):
                vuln.add_sources(pattern['sources'])
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