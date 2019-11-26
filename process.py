from taint import Taintdness
from detection import detect

def process_name_left(instruction):
    return instruction['id'] 

def process_name_right(instruction, processed):
    return processed[instruction['id']] if processed[instruction['id']] != {} else instruction['id']

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
        #Se for var ou função, o que fazemos???? Taint a tudo because we have no clue ou solução mais avançada
        return -1

def process_value(instruction):
    if(instruction['ast_type'] == 'Name'):
        return process_name_left(instruction)
    elif(instruction['ast_type'] == 'Subscript'):
        return process_subscript(instruction)

def process_subscript(instruction):
    index = process_index(instruction['slice']['value'])
    value = process_value(instruction['value'])
    #create object???  use isinstance in main??? (necessary to correct in order to access collections in the dictionary var)
    #TODO
    var = value + '[' + str(index) + ']'
    return var

def process_tuple(instruction, processed, isRight):
    var = []
    for elt in instruction['elts']:
        var += [processing(elt, processed, isRight)]
    return tuple(var)

def process_list(instruction, processed):
    l = []
    for elt in instruction['elts']:
        l.append(processing(elt, processed))
    return l

def process_set(instruction, processed):
    elts = instruction['elts']
    s = {processing(elts[0], processed)}
    for i in range(1, len(elts)):
        s.add(processing(elts[i], processed))
    return s

def process_dicti(instruction, processed):
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
        vals.append(processing(value, processed))
    dicti = {}
    for i in range(0, len(keys)):
        dicti[keys[i]] = vals[i]
    return dicti

def process_calls(instruction, f_name, processed):
    vuln_sinks = detect(f_name, vulns, "sinks")
    if vuln_sinks != []:
        for arg in instruction['args']:
            aux = [x for x in vuln_sinks if x in processing(arg, processed).get_vulns()] 
            if aux != []:
               print(aux[0]) #FAZER RETURN FINAL
               #TODO
            #check if it is var
            elif(isinstance(aux, str)):
                #if it is unknown, it could be a source just like in the project example
                if processed[aux] == {}:
                    return Taintdness(True, source = aux, sink=f_name)
    

def process_func(instruction, processed):
    f_name = processing(instruction['func'], processed, False)
    
    vuln_sources = detect(f_name, vulns, "sources")
    if vuln_sources != []:
        return Taintdness(True, vuln = vuln_sources, source = f_name)
    
    process_calls(instruction, f_name, processed)
    
    vuln_sanitizers = detect(f_name, vulns, "sanitizers")
    if vuln_sanitizers != []:
        for arg in instruction['args']:
            taint = processing(arg, processed)
            aux = [x for x in vuln_sanitizers if x in taint.get_vulns()]
            if aux != []:
               taint.add_sanitizers(f_name)
               return taint
            
    
    return Taintdness()
     

def process_assign(instruction, vulnerabilities, user_functions, processed):
    global vulns
    vulns = vulnerabilities
    global user_funcs
    user_funcs = user_functions
    var = []
    for target in instruction['targets']:
        '''Name, tuple, Subscript (Que tenha descoberto)'''
        #Examplos para dictionary, tuples, etc
        if target['ast_type'] == 'Name':
            var.append([process_name_left(target)])
            
        elif target['ast_type'] == 'Tuple':
            var.append([process_tuple(target, processed, False)])
            
        elif target['ast_type'] == 'Subscript':
            var.append([process_subscript(target)])
                
    value = instruction['value']
    #type bytes
    vals = [[processing(value, processed)]]
    
    dicti = {}
    
    for i in range(len(var)):
       for j in range(len(var[i])):
           if isinstance(var[i][j], tuple):
               for k in range(len(var[i][j])):
                   dicti[var[i][j][k]] = vals[i][j][k]
           else:
               dicti[var[i][j]] = vals[i][j]
    #print(dicti) 
    return dicti

def processing(instruction, processed, isRight = True):
    #type bytes
    if(isinstance(instruction, str)):
        return Taintdness(False, "", "", "", "")
    elif(instruction['ast_type'] == 'Name'):
        return process_name_right(instruction, processed) if isRight else process_name_left(instruction)
    
    elif(instruction['ast_type'] == 'Tuple'):
        return process_tuple(instruction, processed, True)
    
    elif(instruction['ast_type'] == 'Subscript'):
        return process_subscript(instruction, processed)
    
    elif(instruction['ast_type'] == 'Num'):
        return process_num(instruction)
    
    elif(instruction['ast_type'] == 'Str'):
        return process_str(instruction)
    
    elif(instruction['ast_type'] == 'NameConstant'):
        return process_boolean(instruction)
    
    elif(instruction['ast_type'] == 'List'):
        return process_list(instruction, processed)
    
    elif(instruction['ast_type'] == 'Dict'):
        return process_dicti(instruction, processed)
    
    elif(instruction['ast_type'] == 'Set'):
        return process_set(instruction, processed)
    
    elif(instruction['ast_type'] == 'Call'):
        return process_func(instruction, processed)
    #process function, binary_ops
