def process_name(instruction):
    return instruction['id']

def process_str(instruction):
    string = "\"" + instruction['s'] + "\""
    return string

def process_int(instruction):
    return instruction['n']

def process_num(instruction):
    if(instruction['ast_type'] == 'int'):
        return process_int(instruction)

def process_index(instruction):
    if(instruction['ast_type'] == 'Num'):
        return process_num(instruction['n'])
    elif(instruction['ast_type'] == 'Str'):
        return process_str(instruction)
    else:
        #Se for var, o que fazemos???? Taint a tudo because we have no clue ou solução mais avançada
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
        if(elt['ast_type'] == 'Name'):
            var = var + (process_name(elt))
        elif(elt['ast_type'] == 'Subscript'):
            var = var + (process_subscript(elt))
        elif(elt['ast_type'] == 'Num'):
            var = var + (process_num(elt))
        elif(elt['ast_type'] == 'Str'):
            var = var + (process_str(elt))
    return var

def process_list(instruction):
    l = []
    for elt in instruction['elts']:
        if(elt['ast_type'] == 'Name'):
            l.append(process_name(elt))
        elif(elt['ast_type'] == 'Str'):
            l.append(process_str)
        elif(elt['ast_type'] == 'List'):
            l.append(process_list(elt))
        elif(elt['ast_type'] == 'Tuple'):
            l.append(process_tuple(elt))
            #process dictionary, set, function, booleans, binary_ops
    return l    

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
    if(value['ast_type'] == 'Name'):
        vals = [process_num(value)]
    elif(value['ast_type'] == 'Tuple'):
        vals = process_tuple(value)
    elif(value['ast_type'] == 'Subscript'):
        vals = [process_subscript(value)]
    elif(value['ast_type'] == 'Num'):
        vals = [process_num(value)]
    elif(value['ast_type'] == 'Str'):
        vals = [process_str(value)]
    #acabar!!!



