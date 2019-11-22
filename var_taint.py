class Var_taint:
    def __init__(self, taint, source, input_var, sanitizer):
        self.taint = taint
        self.source = source
        self.input_var = input_var
        self.sanitizer = sanitizer

    