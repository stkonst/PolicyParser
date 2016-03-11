from collections import namedtuple, deque
import copy

import errors
import analyzer

AS, AS_SET, AS_PATH, PREFIX_LIST, RS_SET = (
    'AS AS_set  AS_PATH  prefix_list  rs_set'.split())

op_details = namedtuple('op_details', 'precedence associativity')

ops = {
    'NOT': op_details(precedence=3, associativity='Right'),
    'AND': op_details(precedence=2, associativity='Left'),
    'OR': op_details(precedence=1, associativity='Left'),
}


class Condition():

    def __init__(self, allow, category, data):
        """Condition of a Term.

        Category can be one of the following:
            * PREFIX_LIST
            * RS_SET
            * AS
            * AS_SET
            * AS_PATH

        Parameters
        ----------
        allow : True or False
            The policy for the given match.
        category : str
            The category of the condition.
        data : list
            Contains the required data.
        """
        self.allow = allow
        self.category = category
        self.data = data


class Term():

    def __init__(self, allow):
        """Term of the evaluated filter. It is a constructing part of the filter
        and groups Conditions under the same policy.

        Parameters
        ----------
        allow : True or False
            The policy for the included members,
        """
        self.allow = allow
        self.members = []


def OR(queue, depth):
    """Performs the OR functionality of RPSL on queue's next two nodes."""
    try:
        a = queue.pop()
        a, a_depth = execute_node(a, queue, depth)
        b = queue.pop()
        b, b_depth = execute_node(b, queue, depth)
    except IndexError:
        raise errors.FilterCompositionError("Not enough operands for operation <OR>!")

    max_depth = max(a_depth, b_depth)
    if max_depth >= 2:
        raise errors.UnimplementedError("More depth ({}) in operations than we can handle!".format(max_depth))

    def evaluate_simple_operand_with_operation(simple_operand, operation, check_nested_NOT=False):
        """Put the simple operand at the front or rear of the result depending
           on its policy.
        """
        result = deque()
        for op_term in operation:
            if check_nested_NOT:
                if op_term.allow:
                    result.append(op_term)
                else:
                    raise errors.UnimplementedError("No support for nested operation which includes NOT!")
            else:
                result.append(op_term)
        term = Term(simple_operand.allow)
        term.members = [simple_operand]
        if term.allow:
            result.appendleft(term)
        else:
            result.append(term)
        return result

    def evaluate_AND_with_OR(and_operation, or_operation):
        """ Move the AND's terms to the result and add the OR's terms;
            allowed at the front, denied at the rear.
            NOTE: All the nested AND's terms are expected to be allowed!
        """
        result = deque()
        for and_term in and_operation:
            if and_term.allow:
                result.append(and_term)
            else:
                raise errors.UnimplementedError("No support for nested operation which includes NOT!")
        for or_term in or_operation:
            if or_term.allow:
                result.appendleft(or_term)
            else:
                result.append(or_term)
        return result

    def evaluate_OR_with_OR(or_operation_1, or_operation_2):
        """ The result is populated with all the terms. Allowed terms are put at
            the start.
        """
        result = deque()
        for or_operation in [or_operation_1, or_operation_2]:
            for or_term in or_operation:
                if or_term.allow:
                    result.appendleft(or_term)
                else:
                    result.append(or_term)
        return result

    def evaluate_AND_with_AND(and_operation_1, and_operation_2):
        """ The result is populated with all the terms.
            NOTE: All the nested AND's terms are expected to be allowed!
        """
        result = []
        for and_operation in [and_operation_1, and_operation_2]:
            for and_term in and_operation:
                if and_term.allow:
                    result.append(and_term)
                else:
                    raise errors.UnimplementedError("No support for nested operation which includes NOT!")
        return result

    result = deque()
    simple_operands = []
    temp_result = []

    # Operand 'a'
    if a[0] in ['AND', 'OR']:
        temp_result = a
    elif a[0] == 'OPERAND':
        simple_operands.append(a[1])
    else:
        raise errors.FilterCompositionError("Unkown operand: '{}'".format(a[0]))

    # Operand 'b'
    if b[0] =='OR':
        # If 'a' was a simple operand.
        if simple_operands:
            result = evaluate_simple_operand_with_operation(
                    simple_operands.pop(), b[1])
        elif temp_result:
            # If 'a' was an OR operation.
            if temp_result[0] == 'OR':
                result = evaluate_OR_with_OR(temp_result[1], b[1])
            # If 'a' was an AND operation.
            elif temp_result[0] == 'AND':
                result = evaluate_AND_with_OR(temp_result[1], b[1])
            else:
                raise errors.FilterCompositionError("Unknown operation '{}'".format(temp_result[0]))

    elif b[0] == 'AND':
        max_depth += 1
        # If 'a' was a simple operand.
        if simple_operands:
            result = evaluate_simple_operand_with_operation(
                    simple_operands.pop(), b[1], check_nested_NOT=True)
        elif temp_result:
            # If 'a' was an OR operation.
            if temp_result[0] == 'OR':
                result = evaluate_AND_with_OR(b[1], temp_result[1])
            elif temp_result[0] == 'AND':
                result = evaluate_AND_with_AND(b[1], temp_result[1])
            else:
                raise errors.FilterCompositionError("Unknown operation '{}'".format(temp_result[0]))

    elif b[0] == 'OPERAND':
        if temp_result:
            if temp_result[0] == 'OR':
                result = evaluate_simple_operand_with_operation(
                        b[1], temp_result[1])
            elif temp_result[0] == 'AND':
            # NOTE: As of now, the nested AND operations are expected to only
            # have allowed terms!
                result = evaluate_simple_operand_with_operation(
                        b[1], temp_result[1], check_nested_NOT=True)
            else:
                raise errors.FilterCompositionError("Unknown operation '{}'".format(temp_result[0]))
        # If both operands are simple also add this to the simple_operands list.
        else:
            simple_operands.append(b[1])

    else:
        raise errors.FilterCompositionError("Unkown operand: '{}'".format(a[0]))

    # Only True when *both* operands are simple operands. Otherwise the simple
    # operands are consumed from the operations above.
    while simple_operands:
        simple_operand = simple_operands.pop()
        term = Term(simple_operand.allow)
        term.members = [simple_operand]
        if term.allow:
            result.appendleft(term)
        else:
            result.append(term)

    return (('OR', result), max_depth)


def AND(queue, depth):
    """Performs the AND functionality of RPSL on queue's next two nodes."""
    try:
        a = queue.pop()
        a, a_depth = execute_node(a, queue, depth)
        b = queue.pop()
        b, b_depth = execute_node(b, queue, depth)
    except IndexError:
        raise errors.FilterCompositionError("Not enough operands for operation <AND>!")

    max_depth = max(a_depth, b_depth)
    if max_depth >= 2:
        raise errors.UnimplementedError("More depth ({}) in operations than we can handle!".format(max_depth))

    def evaluate_simple_operand_with_operation(simple_operand, operation, check_nested_NOT=False):
        """ If the simple operand is allowed append it to all the allowed terms,
            else put it at the start.
            NOTE: All nested OR's terms are expected to be true!
        """
        result = []
        if simple_operand.allow:
            for op_term in operation:
                if op_term.allow:
                    op_term.members.append(simple_operand)
                elif check_nested_NOT and not op_term.allow:
                    raise errors.UnimplementedError("No support for nested operation which includes NOT!")
                result.append(op_term)
        else:
            term = Term(simple_operand.allow)
            term.members = [simple_operand]
            result.append(term)
            for op_term in operation:
                if check_nested_NOT and not op_term.allow:
                    raise errors.UnimplementedError("No support for nested operation which includes NOT!")
                else:
                    result.append(op_term)
        return result

    def evaluate_AND_with_OR(and_operation, or_operation):
        """ For every OR's term and every allowed AND's term create a new term
            with both members.
            NOTE: All the nested OR's terms are expected to be allowed!
        """
        result = []
        for and_term in and_operation:
            if and_term.allow:
                for or_term in or_operation:
                    if or_term.allow:
                        new_term = copy.deepcopy(and_term)
                        new_term.members.extend(or_term.members)
                        result.append(new_term)
                    else:
                        raise errors.UnimplementedError("No support for nested operation which includes NOT!")
            else:
                result.append(and_term)
        return result

    def evaluate_AND_with_AND(and_operation_1, and_operation_2):
        """ All the reject terms are put at the start of the result and all the
            allowed terms are combined together.
        """
        result = deque()
        seen_all_and_2_terms = False
        for and_1_term in and_operation_1:
            if and_1_term.allow:
                for and_2_term in and_operation_2:
                    if and_2_term.allow:
                        seen_all_and_2_terms = True
                        and_1_term.members.extend(and_2_term.members)
                result.append(and_1_term)
            else:
                result.appendleft(and_1_term)
        for and_2_term in and_operation_2:
            if not and_2_term.allow:
                result.appendleft(and_2_term)
            elif not seen_all_and_2_terms:
                result.append(and_2_term)
        return result

    def evaluate_OR_with_OR(or_operation_1, or_operation_2):
        """ For OR's every term create new terms equal to the number of the other
            OR's terms.
            NOTE: All the nested OR's terms are expected to be allowed!
        """
        result = []
        for or_1_term in or_operation_1:
            for or_2_term in or_operation_2:
                new_term = Term(or_1_term.allow)
                new_term.members.extend(or_1_term.members)
                new_term.members.extend(or_2_term.members)
                result.append(new_term)
        return result

    result = deque()
    simple_operands = []
    temp_result = []

    # Operand 'a'
    if a[0] in ['AND', 'OR']:
        temp_result = a
    elif a[0] == 'OPERAND':
        simple_operands.append(a[1])
    else:
        raise errors.FilterCompositionError("Unkown operand: '{}'".format(a[0]))

    # Operand 'b'
    if b[0] == 'OR':
        max_depth += 1
        # If 'a' was a simple operand.
        if simple_operands:
            result = evaluate_simple_operand_with_operation(
                    simple_operands.pop(), b[1], check_nested_NOT=True)
            # ...create a Term for the simple operand...
            #simple_operand = simple_operands.pop()
            #term = Term(simple_operand.allow)
            #term.members = [simple_operand]
            ## ...and if it is allowed append it to every allowed term's
            ## members.
            #if simple_operand.allow:
            #    for b_term in b[1]:
            #        if b_term.allow:
            #            b_term.members.append(simple_operand)
            #            result.append(b_term)
            #        else:
            #            raise errors.UnimplementedError("No support for nested operation which includes NOT!")
            ## ...else append it at the start of the result.
            #else:
            #    result.appendleft(term)
            #    for b_term in b[1]:
            #        if b_term.allow:
            #            result.append(b_term)
            #        else:
            #            raise errors.UnimplementedError("No support for nested operation which includes NOT!")
        elif temp_result:
            # If 'a' was an OR operation.
            if temp_result[0] == 'OR':
                result = evaluate_OR_with_OR(temp_result[1], b[1])
            # If 'a' was an AND operation.
            elif temp_result[0] == 'AND':
                result = evaluate_AND_with_OR(temp_result[1], b[1])
                #for temp_term in temp_result[1]:
                #    if temp_term.allow:
                #        for b_term in b[1]:
                #            if b_term.allow:
                #                new_term = copy.deepcopy(temp_term)
                #                new_term.members.extend(b_term.members)
                #                result.append(new_term)
                #            else:
                #                raise errors.UnimplementedError("No support for nested operation which includes NOT!")
                #    else:
                #        result.append(temp_term)
            else:
                raise errors.FilterCompositionError("Unknown operation '{}'".format(temp_result[0]))

    elif b[0] == 'AND':
        # If 'a' was a simple operand...
        if simple_operands:
            result = evaluate_simple_operand_with_operation(
                    simple_operands.pop(), b[1])
            #simple_operand = simple_operands.pop()
            ## ...and its policy is allowed, then append 'a' to all allowed terms.
            #if simple_operand.allow:
            #    for b_term in b[1]:
            #        if b_term.allow:
            #            b_term.members.append(simple_operand)
            #        result.append(b_term)
            ## ...else create a new reject Term and put him at the start.
            #else:
            #    term = Term(simple_operand.allow)
            #    term.members = [simple_operand]
            #    result.appendleft(term)
            #    for b_term in b[1]:
            #        result.append(b_term)
        elif temp_result:
            # If 'a' was an OR operation.
            if temp_result[0] == 'OR':
                result = evaluate_AND_with_OR(b[1], temp_result[1])
                #for b_term in b[1]:
                #    if b_term.allow:
                #        for temp_term in temp_result[1]:
                #            if temp_term.allow:
                #                new_term = copy.deepcopy(b_term)
                #                new_term.members.extend(temp_term.members)
                #                result.append(new_term)
                #            else:
                #                raise errors.UnimplementedError("No support for nested operation which includes NOT!")
                #    else:
                #        result.append(b_term)
            # If 'a' was an AND operation.
            elif temp_result[0] == 'AND':
                result = evaluate_AND_with_AND(temp_result[1], b[1])
                #seen_all_b_terms = False
                ## ...for every term in 'a'...
                #for temp_term in temp_result[1]:
                #    # ...if its policy is allowed we extend its members with
                #    # 'b' members that are allowed.
                #    if temp_term.allow:
                #        for b_term in b[1]:
                #            if b_term.allow:
                #                seen_all_b_terms = True
                #                temp_term.members.extend(b_term.members)
                #        result.append(temp_term)
                #    # ...else we put it into the start.
                #    else:
                #        result.appendleft(temp_term)
                ## At the end we put ('b')'s reject policies at the start, and
                ## any ('b')'s allow policies that were not appended, at the end.
                #for b_term in b[1]:
                #    if not b_term.allow:
                #        result.appendleft(b_term)
                #    elif not seen_all_b_terms:
                #        result.append(b_term)

    elif b[0] == 'OPERAND':
        # If 'a' was an operation...
        if temp_result:
            if temp_result[0] == 'OR':
                result = evaluate_simple_operand_with_operation(
                        b[1], temp_result[1], check_nested_NOT=True)
            elif temp_result[0] == 'AND':
                result = evaluate_simple_operand_with_operation(
                        b[1], temp_result[1])
            else:
                raise errors.FilterCompositionError("Unknown operation '{}'".format(temp_result[0]))
            #simple_operand = b[1]
            ## ...and ('b')'s  policy is allowed, then append 'b' to all allowed
            ## terms.
            #if simple_operand.allow:
            #    for temp_term in temp_result[1]:
            #        if temp_term.allow:
            #            temp_term.members.append(simple_operand)
            #        result.append(temp_term)
            ## ...else create a new reject Term and put it at the start.
            #else:
            #    for temp_term in temp_result[1]:
            #        result.append(temp_term)
            #    term = Term(simple_operand.allow)
            #    term.members = [simple_operand]
            #    result.appendleft(term)
        # If both operands are simple also add this to the simple_operands list.
        else:
            simple_operands.append(b[1])

    else:
        raise errors.FilterCompositionError("Unkown operand: '{}'".format(a[0]))

    # Only True when *both* operands are simple operands. Otherwise the simple
    # operands are consumed from the operations above.
    while simple_operands:
        simple_operand = simple_operands.pop()
        if not result:
            term = Term(simple_operand.allow)
            term.members = [simple_operand]
            result.append(term)
        else:
            if result[0].allow and simple_operand.allow:
                result[0].members.append(simple_operand)
            else:
                term = Term(simple_operand.allow)
                term.members = [simple_operand]
                if term.allow:
                    result.append(term)
                else:
                    result.appendleft(term)

    return (('AND', result), max_depth)


def NOT(queue, depth):
    """Performs the NOT functionality of RPSL on queue's next node.

    .. warning:: Currently supports only NOT'ing a single operand.
    """

    try:
        a = queue.pop()
        if a[0] in ['AND', 'OR']:
            raise errors.UnimplementedError("NOT'ing a non simple operand is not yet suported!")
        a, a_depth = execute_node(a, queue, depth)
    except IndexError:
        raise errors.FilterCompositionError("Not enough operands for operation <NOT>!")

    if a_depth >= 2:
        raise errors.UnimplementedError("More depth ({}) in operations than we can handle!".format(a_depth))

    if a[0] in ['AND', 'OR']:
        pass
        # XXX Not supported functionality! Keep here for now!
        #result = deque()
        #for term in a[1]:
        #    if term.allow:
        #        for member in term.members:
        #            new_term = Term(not term.allow)
        #            new_term.members = [member]
        #            result.appendleft(new_term)
        #    else:
        #        term.allow = not term.allow
        #        result.append(term)
        #return (a[0], result)
    else:
        a[1].allow = False
        return ((a[0], a[1]), a_depth)


def execute_node(node, queue, depth):
    """Evaluates the current node."""
    if node[0] == 'OR':
        return OR(queue, depth)
    elif node[0] == 'AND':
        return AND(queue, depth)
    elif node[0] == 'NOT':
        return NOT(queue, depth)
    else:
        return (('OPERAND', Condition(True, node[0], node[1])), depth)


def compose_filter(output_queue):
    """Composes the required filter structure from the Shunting-Yard algorithm output.

    Parameters
    ----------
    output_queue : list
        The Shunting-Yard output for a given filter.

    Returns
    -------
    result : list
        A list containing Terms in order.

    Raises
    ------
    FilterCompositionError
        When the input queue is invalid.
    UnimplementedError
        When the code reaches unimplemented functionality.
    """
    if not queue:
        raise errors.FilterCompositionError("Provided empty queue as input!")

    node = queue.pop()
    if node[0] not in ops:
        raise errors.FilterCompositionError("Invalid queue. The queue's tail must be an operator!")

    starting_depth = 1
    result, _ = execute_node(node, queue, starting_depth)
    #ordered = sorted(result[1], key=sort_members)
    #result = (result[0], ordered)
    return result


if __name__ == "__main__":
    TEST_STRING_1 = "AS1 AND AS2 AND AS3"
    TEST_STRING_2 = "NOT AS1 AND AS2 AND NOT AS3"
    TEST_STRING_3 = "AS1 AND NOT AS2 AND AS3"

    TEST_STRING_4 = "AS1 OR AS2 OR AS3"
    TEST_STRING_5 = "NOT AS1 OR AS2 OR NOT AS3"
    TEST_STRING_6 = "AS1 OR NOT AS2 OR AS3"

    TEST_STRING_7 = "AS1 AND AS2 AND (AS4 OR AS5) AND NOT AS3"
    TEST_STRING_8 = "AS1 AND AS2 AND (AS4 OR NOT AS5) AND NOT AS3"
    TEST_STRING_9 = "AS1 AND (AS2 OR AS3) AND (AS4 OR AS5)"
    TEST_STRING_10 = "AS1 AND (AS2 OR AS3) AND AS6 AND (AS4 OR AS5)"
    TEST_STRING_11 = "AS1 AND (AS2 OR AS3) AND NOT AS6 AND (AS4 OR AS5)"

    TEST_STRING_12 = "AS1 OR AS2 OR (AS4 AND AS5) OR NOT AS3"
    TEST_STRING_13 = "AS1 OR AS2 OR NOT AS3 OR (AS4 AND NOT AS5) OR (NOT AS6 AND AS7)"
    TEST_STRING_14 = "AS1 OR (AS2 AND AS3) OR (AS4 AND AS5)"
    TEST_STRING_15 = "(AS1 OR AS2) OR (AS3 OR AS4) OR AS5 OR NOT AS6"
    TEST_STRING_16 = "(AS1 AND AS2) AND (AS3 AND AS4) AND AS5 AND NOT AS6"
    TEST_STRING_17 = "(AS0 AND AS1) OR (AS2 AND AS3) OR (AS4 AND AS5)"
    TEST_STRING_18 = "(AS0 OR AS1) AND (AS2 OR AS3) AND (AS4 OR AS5)"
    TEST_STRING_19 = "AS1 OR (AS2 AND AS3) OR AS6 OR (AS4 AND AS5)"
    TEST_STRING_20 = "AS1 OR (AS2 AND AS3) OR NOT AS6 OR (AS4 AND AS5)"

    TEST_STRINGS = [TEST_STRING_1, TEST_STRING_2, TEST_STRING_3, TEST_STRING_4,
                    TEST_STRING_5, TEST_STRING_6, TEST_STRING_7, TEST_STRING_8,
                    TEST_STRING_9, TEST_STRING_10, TEST_STRING_11, TEST_STRING_12,
                    TEST_STRING_13, TEST_STRING_14, TEST_STRING_15, TEST_STRING_16,
                    TEST_STRING_17, TEST_STRING_18, TEST_STRING_19, TEST_STRING_20]

    for i, TEST_STRING in enumerate(TEST_STRINGS):
        try:
            print "--- Filter: {} ---".format(i+1)
            print "Input"
            print "-----"
            print "{}".format(TEST_STRING)
            print
            out, _, _, _ = analyzer.analyze_filter(TEST_STRING)
            #print "Analyzed"
            #print "--------"
            #print "{}".format([ desc if desc in ops else value for desc, value in out])
            #print
            result = compose_filter(out)
            #print "Result"
            #print "------"
            #print "{}".format(result)
            #print
            print "Terms"
            print "-----"
            for term in result[1]:
                print "Allow: {}".format(term.allow)
                print "Members: {}".format([m.data for m in term.members])
                print
            #print "-{}".format(result[0])
            #for x in result[1]:
            #    traverse_result(x, 1)
        except Exception as e:
            print "Error: {}".format(e)
        finally:
            print "--------------------------------"
            print
            print
