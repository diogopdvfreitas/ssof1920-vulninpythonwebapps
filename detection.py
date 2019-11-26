          
def detect(f_name, vulns, pattern_type):
    l = []
    for vuln in vulns:
        if pattern_type == "sinks":
            aux_vuln = vuln.get_sinks()
            
        elif pattern_type == "sources":
            aux_vuln = vuln.get_sources()
            
        elif pattern_type == "sanitizers":
            aux_vuln = vuln.get_sanitizers() 
            
        if f_name in aux_vuln:
            l.append(vuln.get_vulnerability())
            
    return l
            
def get_sanitizer_vuln(sanitizers, vuln, vulns): 
    for v in vulns:
        if(vuln == v.get_vulnerability()):
            vuln = v
            break
    aux_vuln = vuln.get_sanitizers()
    l = [x for x in sanitizers if x in aux_vuln]
    return l
            