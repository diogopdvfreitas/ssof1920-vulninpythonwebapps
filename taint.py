class Taintdness:
    def __init__(self, taint = False, vulns = [], sources = [], sanitizers = [], sinks = []):
        self.taint = taint
        self.vulns = vulns
        self.sources = sources
        self.sanitizers = sanitizers
        self.sinks = sinks
    
    def get_taint(self):
        return self.taint

    def get_vulns(self):
        return self.vulns

    def set_vulns(self, vulns):
        self.vulns = vulns

    def add_vulns(self, vulns):
        for vuln in vulns:
            if vuln not in self.vulns:
                self.vulns = self.vulns + vulns

    def get_sources(self):
        return self.sources

    def set_sources(self, sources):
        self.sources = sources

    def add_sources(self, sources):
        for source in sources:
            if source not in self.sources:
                self.sources = self.sources + sources

    def get_sanitizers(self):
        return self.sanitizers

    def set_sanitizers(self, sanitizers):
        self.sanitizers = sanitizers
     
    def add_sanitizers(self, sanitizers):
        for sanitizer in sanitizers:
            if sanitizer not in self.sanitizers:
                self.sanitizers = self.sanitizers + sanitizers
    
    def get_sinks(self):
        return self.sinks

    def set_sinks(self, sinks):
        self.sinks = sinks

    def add_sinks(self, sinks):
        for sink in sinks:
            if sink not in self.sinks:
                self.sinks = self.sinks + sinks

    def __repr__(self):
        return 'Taintdness:(taint=' + str(self.taint) + ' source=' + str(self.sources) + ' sanitizers=' + str(self.sanitizers) + ' sink=' + str(self.sinks) + ')'

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