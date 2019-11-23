class Taintdness:
    def __init__(self, taint, source, sanitizer, sink, param):
        self.taint = taint
        self.source = source
        self.sanitizer = sanitizer
        self.sink = sink
        self.param = param
    
    def set_sanitizer(self, sanitizer):
        self.sanitizer = sanitizer
    
    def set_sink(self, sink):
        self.sink = sink
    
    def get_taint(self):
        return self.taint

    def get_source(self):
        return self.source

    def get_sanitizer(self):
        return self.sanitizer

    def get_sink(self):
        return self.sink
    
    def get_param(self):
        return self.param

    def __repr__(self):
        return 'Taintdness:(taint=' + str(self.taint) + ' source=' + self.source + ' sanitizer=' + self.sanitizer + \
                ' sink=' + self.sink + ' param=' + self.param + ')'


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
    