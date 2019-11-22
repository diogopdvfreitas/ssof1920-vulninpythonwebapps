def process_name(instruction):
    return instruction['id']

def process_str(instruction):
    string = "\"" + instruction['s'] + "\""
    #return string
    return "\"untaint\""

def process_boolean(instruction):
    #return instruction['value']
    return "\"untaint\""

def process_float(instruction):
    #return instruction['n']
    return "\"untaint\""

def process_int(instruction):
    #return instruction['n']
    return "\"untaint\""

def process_complex(instruction):
    return "\"untaint\""
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
        return process_num(instruction['n'])
    elif(instruction['ast_type'] == 'Str'):
        return process_str(instruction)
    else:
        #Se for var ou função, o que fazemos???? Taint a tudo because we have no clue ou solução mais avançada
        return -1

def process_value(instruction):
    if(instruction['ast_type'] == 'Name'):
        return process_name(instruction)
    elif(instruction['ast_type'] == 'Subscript'):
        return process_subscript(instruction)

def process_subscript(instruction):
    index = process_index(instruction['slice'])
    value = process_value(instruction['value'])
    var = value + '[' + str(index) + ']'
    return var

def process_tuple(instruction):
    var = ()
    for elt in instruction['elts']:
        var = var + (processing(elt),)
    return var

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
        keys.append(processing(key))
    vals = []
    for value in instruction['values']:
        vals.append(processing(value))
    dicti = {}
    for i in range(0, len(keys)):
        dicti[keys[i]] = vals[i]
    return dicti

#acabar
def process_func(instruction):
    func_name = process_name(instruction['func'])

    return "cenas"
    

def process_assign(instruction):
    var = []
    for target in instruction['targets']:
        '''Name, tuple, Subscript (Que tenha descobrido)'''
        #Examplos para dictionary, tuples, etc
        if(target['ast_type'] == 'Name'):
            var.append([process_name(target)])
        elif(target['ast_type'] == 'Tuple'):
            var.append(process_tuple(target))
        elif(target['ast_type'] == 'Subscript'):
            var.append([process_subscript(target)])
                
    value = instruction['value']
    #type bytes
    if(isinstance(value, str)): 
        vals = "\"untaint\""
    elif(value['ast_type'] == 'Tuple'):
        vals = process_tuple(value)
    else:
        vals = [processing(value)]
    
    dicti = {}
    for l in var:
        for i in range(0, len(l)):
            dicti[l[i]] = vals[i]
    print(dicti) 
    return dicti

def processing(instruction):
    #type bytes
    if(isinstance(instruction, str)):
        return "\"untaint\""
    elif(instruction['ast_type'] == 'Name'):
         return process_name(instruction)
    elif(instruction['ast_type'] == 'Tuple'):
        return process_tuple(instruction)
    elif(instruction['ast_type'] == 'Subscript'):
        return process_subscript(instruction)
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
    #process function, binary_ops
