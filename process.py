import cfg
from detection import *
from taint import Taintdness

vulns = ""

def process_name_left(instruction):
    return instruction['id'] 

def process_name_right(instruction):
    if instruction['id'] in cfg.processed.keys():
        return cfg.processed[instruction['id']]
    else:
        return Taintdness(True, sources=[instruction['id']])
    '''Changed -attempt'''
    #return processed[instruction['id']] if instruction['id'] in processed.keys() else instruction['id']

def process_str(instruction):
    #string = "\"" + instruction['s'] + "\""
    #return string
    return Taintdness()

def process_boolean(instruction):
    #return instruction['value']
    return Taintdness()

def process_float(instruction):
    #return instruction['n']
    return Taintdness()

def process_int(instruction):
    #return instruction['n']
    return Taintdness()

def process_complex(instruction):
    return Taintdness()
    #return instruction['i']

def process_num(instruction):
    sub_ins = instruction['n']
    if(sub_ins['ast_type'] == 'int'):
        return process_int(sub_ins)
    elif(sub_ins['ast_type'] == 'float'):
        return process_float(sub_ins)
    elif(sub_ins['ast_type'] == 'complex'):
        return process_complex(sub_ins)

def process_index(instruction):
    if(instruction['ast_type'] == 'Num'):
        return instruction['n']['n']
    elif(instruction['ast_type'] == 'Str'):
        return "\"" + instruction['s'] + "\""
    else:
        #Se for var ou função, o que fazemos???? Taint a tudo because we have no clue ou solução mais avançada propagar???
        #TODO IF PROPAGAR
        return -1

def process_value(instruction):
    if(instruction['ast_type'] == 'Name'):
        return process_name_left(instruction)
    elif(instruction['ast_type'] == 'Subscript'):
        return process_subscript_left(instruction)

def process_subscript_left(instruction):
    index = process_index(instruction['slice']['value'])
    value = process_value(instruction['value'])
    var = value + '[' + str(index) + ']'
    return var

def process_subscript_right(instruction):
    index = process_index(instruction['slice']['value'])
    value = process_value(instruction['value'])
    var = value + '[' + str(index) + ']'
    if var in cfg.processed.keys():
        return cfg.processed[var]
    else:
        return Taintdness(True, sources=[var])

def process_tuple(instruction, isRight):
    var = []
    for elt in instruction['elts']:
        var += [processing(elt, isRight)]
    return tuple(var)

def process_list(instruction):
    l = []
    for elt in instruction['elts']:
        l.append(processing(elt))
    return l

def process_set(instruction):
    elts = instruction['elts']
    s = {processing(elts[0])}
    for i in range(1, len(elts)):
        s.add(processing(elts[i]))
    return s

def process_dicti(instruction):
    keys = []
    for key in instruction['keys']:
        if(key['ast_type'] == 'Num'):
            k = key['n']['n']
        elif(key['ast_type'] == 'Str'):
            k = key['s'] 
        keys.append(k)
        #FIX THIS WHEN FUNCTION
        #TODO
    vals = []
    for value in instruction['values']:
        vals.append(processing(value))
    dicti = {}
    for i in range(0, len(keys)):
        dicti[keys[i]] = vals[i]
    return dicti

""" def process_calls(instruction, f_name, processed):
    vuln_sinks = detect(f_name, vulns, "sinks")
    if vuln_sinks != []:
        for arg in instruction['args']:
            arg_taint = processing(arg, processed) 
            #aux = [x for x in vuln_sinks if x in arg_taint.get_vulns()]
            print(arg_taint) 
            #if aux != []
            if arg_taint.get_taint():
               print("ola")
               for vuln in aux:
                    source = arg_taint.get_sources()
                    sink = f_name
                    sanitizers = arg_taint.get_sanitizers()
                    l = get_sanitizer_vuln(sanitizers, vuln, vulns)
                    sanitizer = ""
                    for san in l:
                        sanitizer += san + " "
                    dicti = {
                        "vulnerability": vuln,
                        "source": source,
                        "sink": sink,
                        "sanitizer": sanitizer
                        }
                    #TODO
                    print([dicti])
            #check if it is var
            elif(isinstance(arg, str)):
                #if it is unknown, it could be a source just like in the project example
                if processed[arg] == {}:
                    return Taintdness(True, sources = aux, sinks = [f_name]) """

def process_calls(instruction, f_name):
    vuln_sinks = detect(f_name, "sinks")
    if vuln_sinks != []:
        for arg in instruction['args']:
            arg_taint = processing(arg)
            if arg_taint.get_taint():
                v = get_vuln(f_name)
                source = arg_taint.get_sources()
                sink = [f_name]
                sanitizers = arg_taint.get_sanitizers()
                dicti = {
                    "vulnerability": v,
                    "source": source,
                    "sink": sink,
                    "sanitizer": sanitizers
                    }
                #TODO
                print([dicti])

def process_func(instruction):
    f_name = processing(instruction['func'], False)
    
    vuln_sources = detect(f_name, "sources")
    if vuln_sources != []:
        return Taintdness(True, vulns = vuln_sources, sources = [f_name])
    
    process_calls(instruction, f_name)
    
    vuln_sanitizers = detect(f_name, "sanitizers")
    if vuln_sanitizers != []:
        for arg in instruction['args']:
            taint = processing(arg)
            aux = [x for x in vuln_sanitizers if x in taint.get_vulns()]
            if aux != []:
               taint.add_sanitizers([f_name])
               return taint
            
    
    return Taintdness()



def process_attribute(instruction):
    lef = processing(instruction['value'])
    a = lef.get_sources()
    k = str(a) + '.' + instruction['attr']
    if k in cfg.processed.keys():
        return cfg.processed[k]
    else:
        return Taintdness(True, sources=lef.get_sources)
    

def process_binaryOp(instruction):
    taint = Taintdness(True)
    left = processing(instruction['left'])
    right = processing(instruction['right'])
    if left.get_taint():
        taint.add_vulns(left.get_vulns())
        taint.add_sources(left.get_sources())
        taint.add_sanitizers(left.get_sanitizers())
        taint.add_sinks(left.get_sinks())
    
    if right.get_taint():
        taint.add_vulns(right.get_vulns())
        taint.add_sources(right.get_sources())
        taint.add_sanitizers(right.get_sanitizers())
        taint.add_sinks(right.get_sinks())
    
    if not left.get_taint() and not right.get_taint():
        taint = Taintdness(False)
    
    return taint

def check_if_collection(val):
    if(isinstance(val, list) or isinstance(val, tuple) or isinstance(val, dict) or isinstance(val, set)):
        return True
    else:
        return False

def p_aux_collections(key, vals):
    dictic = {}
    if(isinstance(vals, list) or isinstance(vals, tuple)):
        for i in range(0,len(vals)):
            k = key + '[' + str(i) + ']'
            if check_if_collection(vals[i]):
                aux = p_aux_collections(k, vals[i])
                dictic = { **dictic, **aux}
            else:
                dictic[k] = vals[i]
    elif(isinstance(vals , set)):
        for i in range(0, len(vals)):
            el = vals.pop()
            k = key + '[' + str(i) + ']'
            if check_if_collection(el):
                aux = p_aux_collections(el, k)
                dictic = { **dictic, **aux}
            else:
                dictic[k] = el
    elif(isinstance(vals, dict)):
        for k in vals:
            ky = key + '[\"' + k + '\"]'
            if check_if_collection(vals[k]):
                aux = p_aux_collections(ky, vals[k])
                dictic = { **dictic, **aux}
            else:
                dictic[ky] = vals[k]
    return dictic


def process_assign(instruction):
    var = []
    for target in instruction['targets']:
        #Examplos para dictionary, tuples, etc
        if target['ast_type'] == 'Name':
            var.append([process_name_left(target)])
            
        elif target['ast_type'] == 'Tuple':
            var.append([process_tuple(target, False)])
            
        elif target['ast_type'] == 'Subscript':
           var.append([process_subscript_left(target)])

    value = instruction['value']
    #type bytes
    vals = [[processing(value)]]
    
    dicti = {}
    
    for i in range(len(var)):
       for j in range(len(var[i])):
           if isinstance(var[i][j], tuple):
               for k in range(len(var[i][j])):
                    if check_if_collection(vals[i][j][k]):
                        aux = p_aux_collections(var[i][j][k], vals[i][j][k])
                        dicti = {**dicti, **aux}
                    else:
                        dicti[var[i][j][k]] = vals[i][j][k]
           else:
                if check_if_collection(vals[i][j]):
                    aux = p_aux_collections(var[i][j], vals[i][j])
                    dicti = {**dicti, **aux}
                else:
                    dicti[var[i][j]] = vals[i][j]
    #print(dicti) 
    return dicti

def processing(instruction, isRight = True):
    #type bytes
    if(isinstance(instruction, str)):
        return Taintdness(False, [], [], [], [])
    elif(instruction['ast_type'] == 'Name'):
        return process_name_right(instruction) if isRight else process_name_left(instruction)
    
    elif(instruction['ast_type'] == 'Tuple'):
        return process_tuple(instruction, True)
    
    elif(instruction['ast_type'] == 'Subscript'):
        return process_subscript_right(instruction)
    
    elif(instruction['ast_type'] == 'Num'):
        return process_num(instruction)
    
    elif(instruction['ast_type'] == 'Str'):
        return process_str(instruction)
    
    elif(instruction['ast_type'] == 'NameConstant'):
        return process_boolean(instruction)
    
    elif(instruction['ast_type'] == 'List'):
        return process_list(instruction)
    
    elif(instruction['ast_type'] == 'Dict'):
        return process_dicti(instruction)
    
    elif(instruction['ast_type'] == 'Set'):
        return process_set(instruction)
    
    elif(instruction['ast_type'] == 'Call'):
        return process_func(instruction)
        
    elif(instruction['ast_type'] == 'Attribute'):
        return process_attribute(instruction)

    elif(instruction['ast_type'] == 'BinOp'):
        return process_binaryOp(instruction)
    #process function, binary_ops
