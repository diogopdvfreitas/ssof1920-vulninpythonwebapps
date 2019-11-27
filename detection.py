import cfg

def detect(f_name, pattern_type):
    l = []
    for vuln in cfg.vulns:
        if pattern_type == "sinks":
            aux_vuln = vuln.get_sinks()
            
        elif pattern_type == "sources":
            aux_vuln = vuln.get_sources()
            
        elif pattern_type == "sanitizers":
            aux_vuln = vuln.get_sanitizers() 
            
        if f_name in aux_vuln:
            l.append(vuln.get_vulnerability())
            
    return l
            
def get_sanitizer_vuln(sanitizers, vuln): 
    """ for v in vulns:
        if(vuln == v.get_vulnerability()):
            vuln = v
            break
    aux_vuln = vuln.get_sanitizers()
    l = [x for x in sanitizers if x in aux_vuln]
    return l """
    aux_vuln = vuln.get_sanitizers()
    l = [x for x in sanitizers if x in aux_vuln]
    return l

def get_vuln(sink):
    for vuln in cfg.vulns:
        if sink in vuln.get_sinks():
            return vuln.get_vulnerability()
        

            