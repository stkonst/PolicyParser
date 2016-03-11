__author__ = 'George Thessalonikefs (george@nlnetlabs.nl) '
import re
from collections import namedtuple

import rpsl
import errors

TEST_STRING_1 = "(AS1 OR AS2) AND <AS1+ AS2*>"
TEST_STRING_2 = "(AS1 OR AS2) AND <AS1+ AS2*> AND <AS99{3,}> AND (AS-3 OR AS-4) AND NOT {192.168.1.0/24, 10.0.0.0/1}dfasdf AND {192.168.1.0/24^-}^26-28"
TEST_STRING_3 = "(AS1 AS2) AND AS3 AS4 RS-12"
TEST_STRING_4 = "(AS1 AS2) AS3 AS4 AND <AS-PATHffnsakdlfa fasdf> {asdf fasdf}"
TEST_STRING_5 = "<^AS1 + ? ~ * ~+ ~? ~* {3,3} AS-set AS* .* .+ .? AS1+ AS1? AS1* AS1{3,3} AS1{3,} AS1{3} AS-set{3,} AS-set* AS-set$>"
TEST_STRING = TEST_STRING_3

GROUP_START = "("
GROUP_END = ")"
ASPATH_START = "<"
ASPATH_END = ">"
PREFIX_START = "{"
PREFIX_END = "}"

AS, AS_SET, AS_PATH, PREFIX_LIST, RS_SET, UNIMPLEMENTED = (
    'AS AS_set  AS_PATH  prefix_list  rs_set  uniplemented'.split())

op_details = namedtuple('op_details', 'precedence associativity')

ops = {
    'NOT': op_details(precedence=3, associativity='Right'),
    'AND': op_details(precedence=2, associativity='Left'),
    'OR': op_details(precedence=1, associativity='Left'),
}


def _explode_filter(filter_text):
    """Explodes the characters in the filter that signify the start/end position
    of certain elements. This will help identify the different elements during
    the Shunting-Yard algorithm.

    These elements are groups (surrounded by parentheses), as-paths (surrounded
    by angle brackets) and prefix lists (surrounded by curly brackets).

    In the case of prefix lists a non-trivial approach is taken in order to
    distinguish prefix list's contents from regex range operators as they are
    both surrounded by curly brackets.

    Args:
        filter_text (str): The filter expression.

    Returns: 
        (str): The exploded filter expression.
    """
    filter_text = filter_text.replace(GROUP_START, ' ' + GROUP_START + ' ')
    filter_text = filter_text.replace(GROUP_END, ' ' + GROUP_END + ' ')
    filter_text = filter_text.replace(ASPATH_START, ' ' + ASPATH_START + ' ')
    filter_text = filter_text.replace(ASPATH_END, ' ' + ASPATH_END + ' ')

    # Below is the procedure to differentiate prefix lists from regex range
    # operators and explode the former.

    # Holds the number of extra space inserted while exploding. Helps navigating
    # the ever-increasing in length filter_text.
    adj = 0

    # Points to the current selection end (regex range operator OR prefix list).
    range_end = -1
    for i, char in list(enumerate(filter_text)):
        i += adj

        # Ignore characters until the selection end. It doesn't add the 'adj'
        # value in  order to ignore the closing curly bracket of the regex range
        # operator but not of the prefix list.
        if i <= range_end:
            continue

        if char == PREFIX_START:
            # print "Found character: {}".format(filter_text)
            # print "                 {}{}".format(' '*(i), '^')
            range_end = filter_text.find(PREFIX_END, i)
            if range_end == -1:
                raise errors.FilterAnalysisError("Non matching curly brackets!")

            # If the enclosing value is not a regex range operator explode the
            # left curly bracket.
            if not re.search("^\d+(?:,\d*)?$", filter_text[i + 1:range_end]):
                filter_text = filter_text[:i] + ' ' + char + ' ' + filter_text[i + 1:]
                adj += 2

                # print "Result:          {}".format(filter_text)
                # print

        # The right curly brackets are only cases of prefix lists. The closing
        # curly brackets of regex range operators are ignored based on the
        # range_end character skipping above.
        elif char == PREFIX_END:
            # print "Found character: {}".format(filter_text)
            # print "                 {}{}".format(' '*(i), '^')
            # We make the assumption that the end of the prefix list (with or
            # without an outer range operator) is separated by space from the
            # next element.
            range_end = filter_text.find(' ', i)

            # If we reached the end of the filter.
            if range_end == -1:
                trail = filter_text[i + 1:]
            else:
                trail = filter_text[i + 1:range_end]

            # If the thing that is stuck onto the PREFIX_END is not a range
            # operator, make some distance.
            if not rpsl.is_pfx_range_operator(trail):
                filter_text = filter_text[:i] + ' ' + char + ' ' + filter_text[i + 1:]
                adj += 2
            else:
                filter_text = filter_text[:i] + ' ' + filter_text[i:]
                adj += 1

                # print "Result:          {}".format(filter_text)
                # print

    return filter_text


def _get_tokens(filter_text, ASes, AS_sets, RS_sets):
    """Constructs a list of identified tokens to be used by the Shunting-Yard
    algorithm.

    Additional actions:
        - Inserts 'OR' where it is ommited to ease calculation later.
        - Updates the given sets with seen values.

    Args:
        filter_text (str): The filter expression.
        ASes (set): The set to update with AS values.
        AS_sets (set): The set to update with AS_set values.

    Returns:
        (list): The identified tokens.

    Raises:
        FilterAnalysisError
    """
    inside_ASPATH = False
    inside_PREFIX = False
    identified_tokens = []

    # Used to determine if the previously pushed identified token
    # was an operator (e.g., 'OR') or a term (e.g., AS, AS-PATH, group of terms)
    pushed_term = False

    tokens = _explode_filter(filter_text).strip().split()
    for token in tokens:
        if token == ASPATH_END:
            if not inside_ASPATH:
                raise errors.FilterAnalysisError("Could not analyze AS-PATH!")

            identified_tokens[-1][1].append(token)
            inside_ASPATH = False
            pushed_term = True

        elif inside_ASPATH:
            if not rpsl.is_as_path_member(token):
                raise errors.FilterAnalysisError(
                    "'{}' is not a valid member of AS-PATH!".format(token))

            identified_tokens[-1][1].append(token)
            pushed_term = False

        # The PREFIX_END may be followed by a range operator.
        elif token[0] == PREFIX_END:
            if not inside_PREFIX:
                raise errors.FilterAnalysisError("Could not analyze PREFIX!")

            if token[1:]:
                identified_tokens[-1][1].append(token[1:])

            inside_PREFIX = False
            pushed_term = True

        elif inside_PREFIX:
            l, sep, r = token.rpartition(',')
            if l and sep:
                token = l

            if not rpsl.is_pfx(token):
                raise errors.FilterAnalysisError("Invalid member '{}' inside PREFIX list!".format(token))

            identified_tokens[-1][1].append(token)
            pushed_term = False

        elif token in ops:
            identified_tokens.append((token, ops[token]))
            pushed_term = False

        elif token == GROUP_END:
            identified_tokens.append((token, op_details(precedence=0, associativity='Left')))
            pushed_term = True

        else:
            if pushed_term:
                identified_tokens.append(('OR', ops['OR']))

            if token == GROUP_START:
                identified_tokens.append((token, op_details(precedence=0, associativity='Left')))
                pushed_term = False

            elif token == ASPATH_START:
                # No need to check if already inside an AS path. Members inside
                # an AS path are validated above.
                inside_ASPATH = True
                identified_tokens.append((AS_PATH, ['<']))
                pushed_term = False

            elif token == PREFIX_START:
                # No need to check if already inside a prefix list. Members
                # inside a prefix list are validated above.
                inside_PREFIX = True
                identified_tokens.append((PREFIX_LIST, []))
                pushed_term = False

            elif rpsl.is_ASN(token):
                identified_tokens.append((AS, token))
                ASes.add(token)
                pushed_term = True

            elif rpsl.is_AS_set(token):
                identified_tokens.append((AS_SET, token))
                AS_sets.add(token)
                pushed_term = True

            elif rpsl.is_rs_set(token):
                identified_tokens.append((RS_SET, token))
                RS_sets.add(token)
                pushed_term = True

            else:
                identified_tokens.append((UNIMPLEMENTED, token))
                pushed_term = True

    if inside_ASPATH:
        raise errors.FilterAnalysisError("AS-PATH is not closed!")
    elif inside_PREFIX:
        raise errors.FilterAnalysisError("PREFIX is not closed!")

    return identified_tokens


def _shunting_yard(tokens):
    """Implementation of Dijkstra's Shunting-Yard algorithm.
    The algorithm is tuned to parse the filter elements of RPSL instead of
    mathematical expressions.

    Args:
        tokens (list): Previously identified tokens of the filter expression.

    Returns:
        (list): The algorithm's output queue (LIFO).

    Raises:
        FilterAnalysisError
    """
    output_queue = []
    operator_stack = []

    for desc, value in tokens:

        if desc == GROUP_START:
            # Put left parentheses in the stack.
            operator_stack.append((desc, value))

        elif desc == GROUP_END:
            # Right parentheses exhaust the stack until the left parentheses is found.
            found_matching_parentheses = False
            while operator_stack:
                operator_2 = operator_stack.pop()
                if operator_2[0] == GROUP_START:
                    found_matching_parentheses = True
                    break
                else:
                    output_queue.append(operator_2)
            if not found_matching_parentheses:
                raise errors.FilterAnalysisError("Mismatched parentheses!")

        elif desc in ops:
            # Operators are checked for their associativity and precedence and
            # put in the stack or output accordingly.
            op1_prec, op1_assoc = value
            while operator_stack:
                _, (op2_prec, _) = operator_stack[-1]
                if (op1_assoc == 'Left' and op1_prec <= op2_prec) or (op1_assoc == 'Right' and op1_prec < op2_prec):
                    output_queue.append(operator_stack.pop())
                else:
                    break
            operator_stack.append((desc, value))

        else:
            # Terms are put in the output queque.
            output_queue.append((desc, value))

    # Exhaust the remaining operators from the stack.
    while operator_stack:
        if operator_stack[-1][0] == GROUP_START:
            raise errors.FilterAnalysisError("Mismatched parentheses!")
        else:
            output_queue.append(operator_stack.pop())

    return output_queue


def analyze_filter(filter_text):
    """Analyzes the filter and runs the Shunting-Yard algorithm to produce a LIFO
    queue that can be used for evaluation.

    Args:
        filter_text (str): The filter expression.

    Returns:
        (list, set, set, set): The result of the Shunting-Yard algorithm as a list (LIFO queue),
                          The set of ASes seen,
                          The set of AS_sets seen,
                          The set of RS_sets seen.
    Raises:
        FilterAnalysisError
    """
    ASes = set()
    AS_sets = set()
    RS_sets = set()
    tokens = _get_tokens(filter_text, ASes, AS_sets, RS_sets)
    output_queue = _shunting_yard(tokens)
    return output_queue, ASes, AS_sets, RS_sets


def compose_filters(output_queue):
    print output_queue
    print "\n\n"
    index = len(output_queue) - 1
    while index >= 0:
        # print output_queue[index]
        if output_queue[index][0] is "OR":
            print "need to add sets"

        elif output_queue[index][0] is "AND":
            print "need to intersect sets"

        elif output_queue[index][0] is "NOT":
            print "need to exclude one set"

        index -= 1
        # pass


if __name__ == "__main__":
    out, ases, assets, rssets = analyze_filter(TEST_STRING)
    # print "out: {}".format([ desc if desc in ops else value for desc, value in out])
    compose_filters(out)
    # print "\n \n"
    # print "out: {}".format([desc for desc, value in out])
    # print "ases: {}".format(ases)
    # print "assets: {}".format(assets)
    # print "rssets: {}".format(rssets)
    compose_filters(out)
