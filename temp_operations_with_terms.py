from collections import deque
import copy

import errors
from analyzer import (
    AS, AS_SET, AS_PATH, PREFIX_LIST, RS_SET, ANY, op_details, ops)


class Condition():
    def __init__(self, allow, category, data):
        """Condition of a Term.

        Category can be one of the following:
            * PREFIX_LIST
            * RS_SET
            * AS
            * AS_SET
            * AS_PATH
            * ANY

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
        """Term of the evaluated filter. It is a constructing part of the
        filter and groups Conditions under the same policy.

        Parameters
        ----------
        allow : True or False
            The policy for the included members,
        """
        self.allow = allow
        self.members = []


def _OR(queue):
    """Performs the OR functionality of RPSL on the queue's next two nodes."""
    try:
        a = queue.pop()
        a, a_has_nested_operation = _execute_node(a, queue)
        b = queue.pop()
        b, b_has_nested_operation = _execute_node(b, queue)
    except IndexError:
        raise errors.FilterCompositionError("Not enough operands for "
                                            "operation <OR>!")

    if a[0] == 'AND' and a_has_nested_operation:
        raise errors.UnimplementedError("More depth in operations than we "
                                        "can handle!")
    elif b[0] == 'AND' and b_has_nested_operation:
        raise errors.UnimplementedError("More depth in operations than we "
                                        "can handle!")

    def evaluate_simple_operand_with_operation(simple_operand, operation,
                                               check_nested_NOT=False):
        """Put the simple operand at the front or rear of the result depending
        on its policy.

        NOTE: All nested AND's terms are expected to be allowed!
        """
        result = deque()
        for op_term in operation:
            if check_nested_NOT and not op_term.allow:
                raise errors.UnimplementedError("No support for nested "
                                                "operation which includes "
                                                "NOT!")
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
        """Move the AND's terms to the result and add the OR's terms;
        allowed at the front, denied at the rear.

        NOTE: All the nested AND's terms are expected to be allowed!
        """
        result = deque()
        for and_term in and_operation:
            if and_term.allow:
                result.append(and_term)
            else:
                raise errors.UnimplementedError("No support for nested "
                                                "operation which includes "
                                                "NOT!")
        for or_term in or_operation:
            if or_term.allow:
                result.appendleft(or_term)
            else:
                result.append(or_term)
        return result

    def evaluate_OR_with_OR(or_operation_1, or_operation_2):
        """The result is populated with all the terms. Allowed terms are put at
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
        """The result is populated with all the terms.

        NOTE: All the nested AND's terms are expected to be allowed!
        """
        result = []
        for and_operation in [and_operation_1, and_operation_2]:
            for and_term in and_operation:
                if and_term.allow:
                    result.append(and_term)
                else:
                    raise errors.UnimplementedError("No support for nested "
                                                    "operation which includes "
                                                    "NOT!")
        return result

    def handle_ANY(result):
        """Handles ANY's existence in the result.

        If ANY is a member of:
        - an allowed term, a term with ANY as its sole member is returned as
                           the result,
        - a non allowed term, that term is discarded.
        """
        for term in result:
            for term_member in term.members:
                if term_member.category == ANY:
                    if term.allow:
                        new_term = Term(term.allow)
                        new_term.members = [term_member]
                        result = [new_term]
                    else:
                        result = [t for t in result if t != term]
                    return result
        return result

    result = deque()
    simple_operands = []
    temp_result = []
    has_nested_operation = False

    # Operand 'a'
    if a[0] == 'OR':
        temp_result = a
    elif a[0] == 'AND':
        has_nested_operation = True
        temp_result = a
    elif a[0] == 'OPERAND':
        simple_operands.append(a[1])
    else:
        raise errors.FilterCompositionError("Unknown operand: "
                                            "'{}'".format(a[0]))

    # Operand 'b'
    if b[0] == 'OR':
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
                raise errors.FilterCompositionError("Unknown operation "
                                                    "'{}'".format(temp_result[0]))

    elif b[0] == 'AND':
        has_nested_operation = True
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
                raise errors.FilterCompositionError("Unknown operation "
                                                    "'{}'".format(temp_result[0]))

    elif b[0] == 'OPERAND':
        if temp_result:
            if temp_result[0] == 'OR':
                result = evaluate_simple_operand_with_operation(
                    b[1], temp_result[1])
            elif temp_result[0] == 'AND':
                result = evaluate_simple_operand_with_operation(
                    b[1], temp_result[1], check_nested_NOT=True)
            else:
                raise errors.FilterCompositionError("Unknown operation "
                                                    "'{}'".format(temp_result[0]))
        # If both operands are simple also add this to the simple_operands
        # list.
        else:
            simple_operands.append(b[1])

    else:
        raise errors.FilterCompositionError("Unknown operand: "
                                            "'{}'".format(a[0]))

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

    result = handle_ANY(result)

    return (('OR', result), has_nested_operation)


def _AND(queue):
    """Performs the AND functionality of RPSL on queue's next two nodes."""
    try:
        a = queue.pop()
        a, a_has_nested_operation = _execute_node(a, queue)
        b = queue.pop()
        b, b_has_nested_operation = _execute_node(b, queue)
    except IndexError:
        raise errors.FilterCompositionError("Not enough operands for "
                                            "operation <AND>!")

    if a[0] == 'OR' and a_has_nested_operation:
        raise errors.UnimplementedError("More depth in operations than we can "
                                        "handle!")
    elif b[0] == 'OR' and b_has_nested_operation:
        raise errors.UnimplementedError("More depth in operations than we can "
                                        "handle!")

    def evaluate_simple_operand_with_operation(simple_operand, operation,
                                               check_nested_NOT=False):
        """If the simple operand is allowed append it to all the allowed terms,
        else put it at the start.

        NOTE: All nested OR's terms are expected to be allowed!
        """
        result = []
        if simple_operand.allow:
            for op_term in operation:
                if op_term.allow:
                    op_term.members.append(simple_operand)
                elif check_nested_NOT:
                    raise errors.UnimplementedError("No support for nested "
                                                    "operation which includes "
                                                    "NOT!")
                result.append(op_term)
        else:
            term = Term(simple_operand.allow)
            term.members = [simple_operand]
            result.append(term)
            for op_term in operation:
                if check_nested_NOT and not op_term.allow:
                    raise errors.UnimplementedError("No support for nested "
                                                    "operation which includes "
                                                    "NOT!")
                else:
                    result.append(op_term)
        return result

    def evaluate_AND_with_OR(and_operation, or_operation):
        """For every OR's term and every allowed AND's term create a new term
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
                        raise errors.UnimplementedError("No support for "
                                                        "nested operation "
                                                        "which includes NOT!")
            else:
                result.append(and_term)
        return result

    def evaluate_AND_with_AND(and_operation_1, and_operation_2):
        """All the reject terms are put at the start of the result and all the
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
        """For OR's every term create new terms equal to the number of the
        other OR's terms.

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

    def handle_ANY(result):
        """Handles ANY's existence in the result.

        If ANY is a member of:
        - an allowed term, ANY is discarded from that term,
        - a non allowed term, a non allowed term with ANY as its sole member is
                              returned as the result.
        """
        for term in result:
            for term_member in term.members:
                if term_member.category == ANY:
                    if term.allow:
                        new_term = Term(term.allow)
                        new_term.members = [m for m in term.members if m != term_member]
                        if new_term.members:
                            result = [t if t != term else new_term for t in result]
                        else:
                            result = [t for t in result if t != term]
                    else:
                        new_term = Term(term.allow)
                        new_term.members = [term_member]
                        result = [new_term]
                    return result
        return result

    result = deque()
    simple_operands = []
    temp_result = []
    has_nested_operation = False

    # Operand 'a'
    if a[0] == 'OR':
        has_nested_operation = True
        temp_result = a
    elif a[0] == 'AND':
        temp_result = a
    elif a[0] == 'OPERAND':
        simple_operands.append(a[1])
    else:
        raise errors.FilterCompositionError("Unknown operand: "
                                            "'{}'".format(a[0]))

    # Operand 'b'
    if b[0] == 'OR':
        has_nested_operation = True
        # If 'a' was a simple operand.
        if simple_operands:
            result = evaluate_simple_operand_with_operation(
                simple_operands.pop(), b[1], check_nested_NOT=True)
        elif temp_result:
            # If 'a' was an OR operation.
            if temp_result[0] == 'OR':
                result = evaluate_OR_with_OR(temp_result[1], b[1])
            # If 'a' was an AND operation.
            elif temp_result[0] == 'AND':
                result = evaluate_AND_with_OR(temp_result[1], b[1])
            else:
                raise errors.FilterCompositionError("Unknown operation "
                                                    "'{}'".format(temp_result[0]))

    elif b[0] == 'AND':
        # If 'a' was a simple operand.
        if simple_operands:
            result = evaluate_simple_operand_with_operation(
                simple_operands.pop(), b[1])
        elif temp_result:
            # If 'a' was an OR operation.
            if temp_result[0] == 'OR':
                result = evaluate_AND_with_OR(b[1], temp_result[1])
            # If 'a' was an AND operation.
            elif temp_result[0] == 'AND':
                result = evaluate_AND_with_AND(temp_result[1], b[1])

    elif b[0] == 'OPERAND':
        if temp_result:
            # If 'a' was an OR operation.
            if temp_result[0] == 'OR':
                result = evaluate_simple_operand_with_operation(
                    b[1], temp_result[1], check_nested_NOT=True)
            # If 'a' was an AND operation.
            elif temp_result[0] == 'AND':
                result = evaluate_simple_operand_with_operation(
                    b[1], temp_result[1])
            else:
                raise errors.FilterCompositionError("Unknown operation "
                                                "'{}'".format(temp_result[0]))
        # If both operands are simple also add this to the simple_operands
        # list.
        else:
            simple_operands.append(b[1])

    else:
        raise errors.FilterCompositionError("Unknown operand: "
                                            "'{}'".format(a[0]))

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

    result = handle_ANY(result)

    return (('AND', result), has_nested_operation)


def _NOT(queue):
    """Performs the NOT functionality of RPSL on queue's next node.

    .. warning:: Currently supports only NOT'ing a single operand.
    """

    try:
        a = queue.pop()
        if a[0] in ['AND', 'OR']:
            raise errors.UnimplementedError("NOT'ing a non simple operand is "
                                            "not yet suported!")
        a, a_has_nested_operation = _execute_node(a, queue)
    except IndexError:
        raise errors.FilterCompositionError("Not enough operands for "
                                            "operation <NOT>!")

    if a[0] in ['AND', 'OR']:
        pass
        # XXX Not supported functionality! Keep here for now!
        # result = deque()
        # for term in a[1]:
        #    if term.allow:
        #        for member in term.members:
        #            new_term = Term(not term.allow)
        #            new_term.members = [member]
        #            result.appendleft(new_term)
        #    else:
        #        term.allow = not term.allow
        #        result.append(term)
        # return (a[0], result)
    else:
        a[1].allow = False
        return ((a[0], a[1]), a_has_nested_operation)


def _execute_node(node, queue):
    """Evaluates the current node."""
    if node[0] == 'OR':
        return _OR(queue)
    elif node[0] == 'AND':
        return _AND(queue)
    elif node[0] == 'NOT':
        return _NOT(queue)
    else:
        return (('OPERAND', Condition(True, node[0], node[1])), False)


def compose_filter(output_queue):
    """Composes the required filter structure from the Shunting-Yard
    algorithm output.

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
    if not output_queue:
        raise errors.FilterCompositionError("Provided empty queue as input!")

    node = output_queue.pop()
    if output_queue and node[0] not in ops:
        raise errors.FilterCompositionError("Invalid queue. The queue's tail "
                                            "must be an operator!")

    result, _ = _execute_node(node, output_queue)
    if result[0] == 'OPERAND':
        term = Term(result[1].allow)
        term.members = [result[1]]
        return [term]
    else:
        return result[1]
