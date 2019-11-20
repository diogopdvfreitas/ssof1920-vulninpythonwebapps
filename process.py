def process_name(instruction):
    return instruction['id']

def process_str(instruction):
    return instruction['s']

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
    if(type(index) == 'int'):
        var = value + '[' + str(index) + ']'
    else:
        var = value + '["' + index + '"]'
    return var
    # var = [[id,index]]
    #ACABAR & Corrigir!!!!

def process_tuple(instruction):
    var = []
    for elt in instruction['elts']:
        if(elt['ast_type'] == 'Name'):
            var.append(process_name(elt))
        elif(elt['ast_type'] == 'Subscript'):
            var.append(process_subscript)
    return var


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
               process_subscript(target)
                
    value = instruction['value']
    '''Num, Tuple, Name, List'''
    #if value['ast_type'] == 'Num':
    #acabar!!!



