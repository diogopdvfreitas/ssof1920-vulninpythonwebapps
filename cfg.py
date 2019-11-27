from read_files import read_patterns

def init_global_variables(pattern_file):
    global vulns
    global processed
    vulns = read_patterns(pattern_file)
    processed = {}
