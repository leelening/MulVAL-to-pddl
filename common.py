def find_predicate(vertices, index):
    string = vertices.values[index - 1, 1]

    return format_string(string)


def format_string(string):
    string = string.replace(' ', '_')
    string = string.replace('(', '_')
    string = string.replace(')', '_')
    string = string.replace('-', '_')
    string = string.replace('\'', '_')
    string = string.replace(',', '_')
    string = string.replace('.', '_')
    string = string.replace('__', '_')
    string = string.replace('__', '_')
    string = string.rstrip('_')
    string = string.lower()
    return string


def predecessor(index, arcs, vertices):
    predecessors = str()
    for (source, target) in arcs:
        if source == index:
            predecessors += ' (' + format_string(find_predicate(vertices, target)) + ' ?x)\n'
    return predecessors


def successor(index, arcs, vertices):
    successors = str()
    for (source, target) in arcs:
        if target == index:
            successors += ' (' + format_string(find_predicate(vertices, source)) + ' ?x)\n'
    return successors
