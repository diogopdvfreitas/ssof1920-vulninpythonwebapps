class Taintdness:
    def __init__(self, taint = False, vuln = [], source = "", sanitizers = [], sink = []):
        self.taint = taint
        self.source = source
        self.sanitizers = sanitizers
        self.sink = sink
        self.vuln = vuln
    
    def set_sanitizers(self, sanitizers):
        self.sanitizers = sanitizers
    
    def set_sink(self, sink):
        self.sink = sink
    
    def set_source(self, source):
        self.source = source
    
    def set_vuln(self, vuln):
        self.vuln = vuln
    
    def get_taint(self):
        return self.taint

    def get_source(self):
        return self.source

    def get_sanitizers(self):
        return self.sanitizers

    def get_sink(self):
        return self.sink
    
    def get_vuln(self):
        return self.vuln
    
    def add_sanitizer(self, sanitizers):
        self.sanitizers.append(sanitizers)
    
    def __repr__(self):
        return 'Taintdness:(taint=' + str(self.taint) + ' source=' + self.source + ' sanitizers=' + str(self.sanitizers) + \
                ' sink=' + str(self.sink) + ')'


def vuln_found(tainted, vulns):
    for vuln in vulns:
        if(vuln.get_sink() == tainted.get_sink()):
            vulnerability = vuln.get_vulnerability()
            break
    source = tainted.get_source()
    sink = tainted.get_sink()
    sanitizer = tainted.get_sanitizer()
    dicti = {
        "vulnerability": vulnerability,
        "source": source,
        "sink": sink,
        "sanitizer": sanitizer
    }
    return dicti


#define function to process lists, sets, tuples and dictionaries

#def 
    