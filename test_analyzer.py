import unittest

import analyzer
import errors


class FilterAnalysisTestCase(unittest.TestCase):
    """Main class to be used when running filter analysis tests."""

    def construct_result(self, out):
        """Creates a list to be compared with the expected result."""
        result = []
        for term in out:
            result.append((term.allow,
                           sorted([m.data for m in term.members])))
        return result

    def run_analysis(self, rpsl):
        """Runs the analysis without any assertion. Used when the result is not
        trivial to compare. Any errors/exception will still be thrown during
        execution.
        """
        out, _, _, _ = analyzer.analyze_filter(rpsl)
        out = analyzer.compose_filter(out)

    def evaluate_result(self, rpsl, expected_result):
        """Runs the analysis and compares the result with the one given."""
        out, _, _, _ = analyzer.analyze_filter(rpsl)
        out = analyzer.compose_filter(out)
        result = self.construct_result(out)
        self.assertListEqual(expected_result, result)

    def evaluate_result_exception(self, rpsl, expected_exception):
        """Runs the analysis and expects and exception to be raised."""
        exception, regex_message = expected_exception
        with self.assertRaisesRegexp(exception, regex_message):
            out, _, _, _ = analyzer.analyze_filter(rpsl)
            out = analyzer.compose_filter(out)


class FilterSyntaxTestCase(FilterAnalysisTestCase):
    """Groups together tests that check for the filter's syntax integrity."""

    def test_empty_filter(self):
        rpsl = ""
        expected_exception = (errors.FilterCompositionError,
                              r"empty queue")
        self.evaluate_result_exception(rpsl, expected_exception)

    def test_missing_parenthesis(self):
        rpsl = "(AS1) AND (AS2 OR AS3"
        expected_exception = (errors.FilterAnalysisError,
                              r"Mismatched parentheses")
        self.evaluate_result_exception(rpsl, expected_exception)

    def test_open_AS_path(self):
        rpsl = "(AS1) AND <AS2 AS3"
        expected_exception = (errors.FilterAnalysisError,
                              r"AS-PATH is not closed")
        self.evaluate_result_exception(rpsl, expected_exception)

    def test_open_prefix_list(self):
        rpsl = "(AS1) AND {0.0.0.0 AND AS2"
        expected_exception = (errors.FilterAnalysisError,
                              r"Mismatched curly brackets")
        self.evaluate_result_exception(rpsl, expected_exception)

    def test_incomplete_NOT(self):
        rpsl = "NOT"
        expected_exception = (errors.FilterCompositionError,
                              r"Not enough operands.*NOT")
        self.evaluate_result_exception(rpsl, expected_exception)

    def test_incomplete_OR(self):
        rpsl = "(AS1 OR) AND AS2"
        expected_exception = (errors.FilterCompositionError,
                              r"Not enough operands.*OR")
        self.evaluate_result_exception(rpsl, expected_exception)

    def test_incomplete_AND(self):
        rpsl = "(AS1 AND) AND AS2"
        expected_exception = (errors.FilterCompositionError,
                              r"Not enough operands.*AND")
        self.evaluate_result_exception(rpsl, expected_exception)


class RPSLObjectsParseTestCase(FilterAnalysisTestCase):
    """Groups together tests that check the identification of RPSL objects."""

    def test_any(self):
        rpsl = "ANY"
        expected_result = [(True, [i]) for i in reversed(rpsl.split())]
        self.evaluate_result(rpsl, expected_result)

    def test_prefix_list_good(self):
        rpsl = ("{0.0.0.0/0} {0.0.0.0/0^-} {0.0.0.0/0^+} "
                "{0.0.0.0/0^12-15, 0.0.0.0/0^+}^12-15 "
                "{12FE:12FE::0/64^31-32}^+ "
                "")
        self.run_analysis(rpsl)

    def test_prefix_list_bad_1(self):
        rpsl = "{0.0.0.0}"
        expected_exception = (errors.FilterAnalysisError,
                              r"Invalid member.*PREFIX list")
        self.evaluate_result_exception(rpsl, expected_exception)

    def test_prefix_list_bad_2(self):
        rpsl = "{0.0.0.0/}"
        expected_exception = (errors.FilterAnalysisError,
                              r"Invalid member.*PREFIX list")
        self.evaluate_result_exception(rpsl, expected_exception)

    def test_prefix_list_bad_3(self):
        rpsl = "{0.0.0.0/0}^"
        expected_exception = (errors.UnimplementedError,
                              r"Unimplemented element")
        self.evaluate_result_exception(rpsl, expected_exception)

    def test_ASes_good(self):
        rpsl = "AS1 AS123"
        expected_result = [(True, [i]) for i in reversed(rpsl.split())]
        self.evaluate_result(rpsl, expected_result)

    def test_ASes_bad_1(self):
        rpsl = "AS"
        expected_exception = (errors.UnimplementedError,
                              r"Unimplemented element")
        self.evaluate_result_exception(rpsl, expected_exception)

    def test_ASes_bad_2(self):
        rpsl = "AS4qwa"
        expected_exception = (errors.UnimplementedError,
                              r"Unimplemented element")
        self.evaluate_result_exception(rpsl, expected_exception)

    def test_AS_sets_good(self):
        rpsl = ("AS-123 AS-abc AS-1b3 AS123:AS-123:AS123:AS-1:AS123 "
                "AS-123:AS123 AS123:AS-123")
        expected_result = [(True, [i]) for i in reversed(rpsl.split())]
        self.evaluate_result(rpsl, expected_result)

    def test_AS_sets_bad_1(self):
        rpsl = "AS-"
        expected_exception = (errors.UnimplementedError,
                              r"Unimplemented element")
        self.evaluate_result_exception(rpsl, expected_exception)

    def test_AS_sets_bad_2(self):
        rpsl = "AS-%^$"
        expected_exception = (errors.UnimplementedError,
                              r"Unimplemented element")
        self.evaluate_result_exception(rpsl, expected_exception)

    def test_AS_sets_bad_3(self):
        rpsl = "AS123:AS123"
        expected_exception = (errors.UnimplementedError,
                              r"Unimplemented element")
        self.evaluate_result_exception(rpsl, expected_exception)

    def test_RS_sets_good(self):
        rpsl = ("RS-123 RS-abc RS-1b3 AS123:RS-123:AS123:RS-1:AS123 "
                "RS-123:AS123 AS123:RS-123")
        expected_result = [(True, [i]) for i in reversed(rpsl.split())]
        self.evaluate_result(rpsl, expected_result)

    def test_RS_sets_bad_1(self):
        rpsl = "RS-"
        expected_exception = (errors.UnimplementedError,
                              r"Unimplemented element")
        self.evaluate_result_exception(rpsl, expected_exception)

    def test_RS_sets_bad_2(self):
        rpsl = "RS123"
        expected_exception = (errors.UnimplementedError,
                              r"Unimplemented element")
        self.evaluate_result_exception(rpsl, expected_exception)

    def test_RS_sets_bad_3(self):
        rpsl = "RS-%^$"
        expected_exception = (errors.UnimplementedError,
                              r"Unimplemented element")
        self.evaluate_result_exception(rpsl, expected_exception)

    @unittest.expectedFailure  # Not supported yet.
    def test_RTR_sets_good(self):
        rpsl = ("RTR-123 RTR-abc RTR-1b3 AS123:RTR-123:AS123:RTR-1:AS123 "
                "RTR-123:AS123 AS123:RTR-123")
        expected_result = [(True, [i]) for i in reversed(rpsl.split())]
        self.evaluate_result(rpsl, expected_result)

    def test_RTR_sets_bad_1(self):
        rpsl = "RTR-"
        expected_exception = (errors.UnimplementedError,
                              r"Unimplemented element")
        self.evaluate_result_exception(rpsl, expected_exception)

    def test_RTR_sets_bad_2(self):
        rpsl = "RTR123"
        expected_exception = (errors.UnimplementedError,
                              r"Unimplemented element")
        self.evaluate_result_exception(rpsl, expected_exception)

    def test_RTR_sets_bad_3(self):
        rpsl = "RTR-%^$"
        expected_exception = (errors.UnimplementedError,
                              r"Unimplemented element")
        self.evaluate_result_exception(rpsl, expected_exception)

    @unittest.expectedFailure  # Not supported yet.
    def test_FLTR_sets_good(self):
        rpsl = ("FLTR-123 FLTR-abc FLTR-1b3 AS123:FLTR-123:AS123:FLTR-1:AS123 "
                "FLTR-123:AS123 AS123:FLTR-123")
        expected_result = [(True, [i]) for i in reversed(rpsl.split())]
        self.evaluate_result(rpsl, expected_result)

    def test_FLTR_sets_bad_1(self):
        rpsl = "FLTR-"
        expected_exception = (errors.UnimplementedError,
                              r"Unimplemented element")
        self.evaluate_result_exception(rpsl, expected_exception)

    def test_FLTR_sets_bad_2(self):
        rpsl = "FLTR123"
        expected_exception = (errors.UnimplementedError,
                              r"Unimplemented element")
        self.evaluate_result_exception(rpsl, expected_exception)

    def test_FLTR_sets_bad_3(self):
        rpsl = "FLTR-%^$"
        expected_exception = (errors.UnimplementedError,
                              r"Unimplemented element")
        self.evaluate_result_exception(rpsl, expected_exception)

    def test_AS_path_good(self):
        rpsl = ("<AS123> <AS-123> <.> <[AS1 AS2]> <[^AS1 AS2]> <^AS1 .* AS2$> "
                "<[AS1-AS2]> <^[^AS-123{1,2} AS1-AS2* AS3]$>"
                "<AS1* AS2+ AS3?> <AS1~* AS2~+ AS2> "
                "<[AS1 AS2]{1} [AS1 AS2]{1,2} [AS1 AS2]{1,}>"
                "<[AS1 AS2]~{1} [AS1 AS2]~{1,2} [AS1 AS2]~{1,}>"
                "")
        self.run_analysis(rpsl)

    @unittest.expectedFailure  # Not supported yet.
    def test_AS_path_should_fail_1(self):
        rpsl = "<AS1 | AS2>"
        self.run_analysis(rpsl)

    @unittest.expectedFailure  # Not supported yet.
    def test_AS_path_should_fail_2(self):
        rpsl = "< (AS1) >"
        self.run_analysis(rpsl)

    def test_AS_path_bad_1(self):
        rpsl = "<RS-123>"
        expected_exception = (errors.FilterAnalysisError,
                              r"Not a valid member .* AS-PATH")
        self.evaluate_result_exception(rpsl, expected_exception)

    def test_AS_path_bad_2(self):
        rpsl = "<qwe>"
        expected_exception = (errors.FilterAnalysisError,
                              r"Not a valid member .* AS-PATH")
        self.evaluate_result_exception(rpsl, expected_exception)

    def test_AS_path_bad_3(self):
        rpsl = "<[AS1-AS2-AS3]>"
        expected_exception = (errors.FilterAnalysisError,
                              r"Not a valid member .* AS-PATH")
        self.evaluate_result_exception(rpsl, expected_exception)

    def test_AS_path_bad_4(self):
        rpsl = "<[AS1-AS2] AS1^->"
        expected_exception = (errors.FilterAnalysisError,
                              r"Not a valid member .* AS-PATH")
        self.evaluate_result_exception(rpsl, expected_exception)


class OperationsTestCase(FilterAnalysisTestCase):
    """Groups together tests that check the operations' result correctness."""

    def test_simple_AND(self):
        rpsl = "AS1 AND AS2 AND AS3"
        expected_result = [
                            (True, sorted(['AS1', 'AS2', 'AS3'])),
                          ]
        self.evaluate_result(rpsl, expected_result)

    def test_simple_AND_NOT_1(self):
        rpsl = "NOT AS1 AND AS2 AND NOT AS3"
        expected_result = [
                            (False, sorted(['AS3'])),
                            (False, sorted(['AS1'])),
                            (True, sorted(['AS2'])),
                          ]
        self.evaluate_result(rpsl, expected_result)

    def test_simple_AND_NOT_2(self):
        rpsl = "AS1 AND NOT AS2 AND AS3"
        expected_result = [
                            (False, sorted(['AS2'])),
                            (True, sorted(['AS1', 'AS3'])),
                          ]
        self.evaluate_result(rpsl, expected_result)

    def test_simple_AND_NOT_3(self):
        rpsl = ("(AS1 AND AS2) AND NOT AS3 AND (AS4 AND AS5) AND AS6 AND "
                "NOT AS7")
        expected_result = [
                            (False, sorted(['AS7'])),
                            (False, sorted(['AS3'])),
                            (True, sorted(['AS1', 'AS2', 'AS4', 'AS5',
                                           'AS6'])),
                          ]
        self.evaluate_result(rpsl, expected_result)

    def test_simple_OR(self):
        rpsl = "AS1 OR AS2 OR AS3"
        expected_result = [
                            (True, sorted(['AS3'])),
                            (True, sorted(['AS2'])),
                            (True, sorted(['AS1'])),
                          ]
        self.evaluate_result(rpsl, expected_result)

    def test_simple_OR_NOT_1(self):
        rpsl = "NOT AS1 OR AS2 OR NOT AS3"
        expected_result = [
                            (True, sorted(['AS2'])),
                            (False, sorted(['AS1'])),
                            (False, sorted(['AS3'])),
                          ]
        self.evaluate_result(rpsl, expected_result)

    def test_simple_OR_NOT_2(self):
        rpsl = "AS1 OR NOT AS2 OR AS3"
        expected_result = [
                            (True, sorted(['AS3'])),
                            (True, sorted(['AS1'])),
                            (False, sorted(['AS2'])),
                          ]
        self.evaluate_result(rpsl, expected_result)

    def test_simple_OR_NOT_3(self):
        rpsl = "(AS1 OR AS2) OR NOT AS3 (AS4 OR AS5) OR AS6 OR NOT AS7"
        expected_result = [
                            (True, sorted(['AS6'])),
                            (True, sorted(['AS1'])),
                            (True, sorted(['AS2'])),
                            (True, sorted(['AS4'])),
                            (True, sorted(['AS5'])),
                            (False, sorted(['AS3'])),
                            (False, sorted(['AS7'])),
                          ]
        self.evaluate_result(rpsl, expected_result)

    def test_ANY_OR_1(self):
        rpsl = "AS1 OR AS2 OR ANY"
        expected_result = [
                            (True, sorted(['ANY'])),
                          ]
        self.evaluate_result(rpsl, expected_result)

    def test_ANY_OR_2(self):
        rpsl = "AS1 OR AS2 OR NOT ANY"
        expected_result = [
                            (True, sorted(['AS2'])),
                            (True, sorted(['AS1'])),
                          ]
        self.evaluate_result(rpsl, expected_result)

    def test_ANY_AND_1(self):
        rpsl = "AS1 AND AS2 AND ANY"
        expected_result = [
                            (True, sorted(['AS1', 'AS2'])),
                          ]
        self.evaluate_result(rpsl, expected_result)

    def test_ANY_AND_2(self):
        rpsl = "AS1 AND AS2 AND NOT ANY"
        expected_result = [
                            (False, sorted(['ANY'])),
                          ]
        self.evaluate_result(rpsl, expected_result)

    def test_ANY_mixed_1(self):
        rpsl = "AS1 AND AS2 OR NOT ANY"
        expected_result = [
                            (True, sorted(['AS1', 'AS2'])),
                          ]
        self.evaluate_result(rpsl, expected_result)

    def test_ANY_mixed_2(self):
        rpsl = "(AS1 OR AS2) AND NOT ANY"
        expected_result = [
                            (False, sorted(['ANY'])),
                          ]
        self.evaluate_result(rpsl, expected_result)

    def test_ANY_mixed_3(self):
        rpsl = "NOT AS0 OR (AS1 AND AS2) OR NOT ANY"
        expected_result = [
                            (True, sorted(['AS1', 'AS2'])),
                            (False, sorted(['AS0'])),
                          ]
        self.evaluate_result(rpsl, expected_result)

    def test_ANY_mixed_4(self):
        rpsl = "NOT AS0 AND (AS1 OR AS2) AND NOT ANY"
        expected_result = [
                            (False, sorted(['ANY'])),
                          ]
        self.evaluate_result(rpsl, expected_result)

    def test_ANY_mixed_5(self):
        rpsl = "AS0 AND (AS1 OR ANY) AND NOT AS2"
        expected_result = [
                            (False, sorted(['AS2'])),
                            (True, sorted(['AS0'])),
                          ]
        self.evaluate_result(rpsl, expected_result)

    def test_ANY_mixed_6(self):
        rpsl = "AS0 OR (AS1 AND ANY) OR NOT AS2"
        expected_result = [
                            (True, sorted(['AS0'])),
                            (True, sorted(['AS1'])),
                            (False, sorted(['AS2'])),
                          ]
        self.evaluate_result(rpsl, expected_result)

    def test_nested_OR_1(self):
        rpsl = "AS1 AND AS2 AND (AS4 OR AS5) AND NOT AS3"
        expected_result = [
                            (False, sorted(['AS3'])),
                            (True, sorted(['AS1', 'AS2', 'AS5'])),
                            (True, sorted(['AS1', 'AS2', 'AS4'])),
                          ]
        self.evaluate_result(rpsl, expected_result)

    def test_nested_OR_2(self):
        rpsl = "AS1 AND NOT AS2 AND (AS4 OR NOT AS5) AND NOT AS3"
        expected_exception = (errors.UnimplementedError,
                              r"No support .* includes NOT")
        self.evaluate_result_exception(rpsl, expected_exception)

    def test_nested_OR_3(self):
        rpsl = "AS1 AND (AS2 OR AS3) AND (AS4 OR AS5)"
        expected_result = [
                            (True, sorted(['AS1', 'AS3', 'AS5'])),
                            (True, sorted(['AS1', 'AS3', 'AS4'])),
                            (True, sorted(['AS1', 'AS2', 'AS5'])),
                            (True, sorted(['AS1', 'AS2', 'AS4'])),
                          ]
        self.evaluate_result(rpsl, expected_result)

    def test_nested_OR_4(self):
        rpsl = "AS1 AND (AS2 OR AS3) AND AS6 AND (AS4 OR AS5)"
        expected_result = [
                            (True, sorted(['AS1', 'AS3', 'AS5', 'AS6'])),
                            (True, sorted(['AS1', 'AS3', 'AS4', 'AS6'])),
                            (True, sorted(['AS1', 'AS2', 'AS5', 'AS6'])),
                            (True, sorted(['AS1', 'AS2', 'AS4', 'AS6'])),
                          ]
        self.evaluate_result(rpsl, expected_result)

    def test_nested_OR_5(self):
        rpsl = "AS1 AND (AS2 OR AS3) AND NOT AS6 AND (AS4 OR AS5)"
        expected_result = [
                            (False, sorted(['AS6'])),
                            (True, sorted(['AS1', 'AS3', 'AS5'])),
                            (True, sorted(['AS1', 'AS3', 'AS4'])),
                            (True, sorted(['AS1', 'AS2', 'AS5'])),
                            (True, sorted(['AS1', 'AS2', 'AS4'])),
                          ]
        self.evaluate_result(rpsl, expected_result)

    def test_nested_OR_6(self):
        rpsl = "(AS0 OR AS1) AND (AS2 OR AS3) AND (AS4 OR AS5)"
        expected_result = [
                            (True, sorted(['AS1', 'AS3', 'AS5'])),
                            (True, sorted(['AS1', 'AS3', 'AS4'])),
                            (True, sorted(['AS0', 'AS3', 'AS5'])),
                            (True, sorted(['AS0', 'AS3', 'AS4'])),
                            (True, sorted(['AS1', 'AS2', 'AS5'])),
                            (True, sorted(['AS1', 'AS2', 'AS4'])),
                            (True, sorted(['AS0', 'AS2', 'AS5'])),
                            (True, sorted(['AS0', 'AS2', 'AS4'])),
                          ]
        self.evaluate_result(rpsl, expected_result)

    def test_nested_AND_1(self):
        rpsl = "AS1 OR AS2 OR (AS4 AND AS5) OR NOT AS3"
        expected_result = [
                            (True, sorted(['AS1'])),
                            (True, sorted(['AS2'])),
                            (True, sorted(['AS4', 'AS5'])),
                            (False, sorted(['AS3'])),
                          ]
        self.evaluate_result(rpsl, expected_result)

    def test_nested_AND_2(self):
        rpsl = ("AS1 OR AS2 OR NOT AS3 OR (AS4 AND NOT AS5) OR "
                "(NOT AS6 AND AS7)")
        expected_exception = (errors.UnimplementedError,
                              r"No support .* includes NOT")
        self.evaluate_result_exception(rpsl, expected_exception)

    def test_nested_AND_3(self):
        rpsl = "AS1 OR (AS2 AND AS3) OR (AS4 AND AS5)"
        expected_result = [
                            (True, sorted(['AS2', 'AS3'])),
                            (True, sorted(['AS1'])),
                            (True, sorted(['AS4', 'AS5'])),
                          ]
        self.evaluate_result(rpsl, expected_result)

    def test_nested_AND_4(self):
        rpsl = "(AS0 AND AS1) OR (AS2 AND AS3) OR (AS4 AND AS5)"
        expected_result = [
                            (True, sorted(['AS2', 'AS3'])),
                            (True, sorted(['AS0', 'AS1'])),
                            (True, sorted(['AS4', 'AS5'])),
                          ]
        self.evaluate_result(rpsl, expected_result)

    def test_nested_AND_5(self):
        rpsl = "AS1 OR (AS2 AND AS3) OR AS6 OR (AS4 AND AS5)"
        expected_result = [
                            (True, sorted(['AS2', 'AS3'])),
                            (True, sorted(['AS1'])),
                            (True, sorted(['AS6'])),
                            (True, sorted(['AS4', 'AS5'])),
                          ]
        self.evaluate_result(rpsl, expected_result)

    def test_nested_AND_6(self):
        rpsl = "AS1 OR (AS2 AND AS3) OR NOT AS6 OR (AS4 AND AS5)"
        expected_result = [
                            (True, sorted(['AS2', 'AS3'])),
                            (True, sorted(['AS1'])),
                            (True, sorted(['AS4', 'AS5'])),
                            (False, sorted(['AS6'])),
                          ]
        self.evaluate_result(rpsl, expected_result)

    def test_more_depth_1(self):
        rpsl = "AS1 OR (AS2 AND (AS3 OR AS4)) OR NOT AS5 OR (AS6 AND AS7)"
        expected_exception = (errors.UnimplementedError,
                              r"More depth .* can handle")
        self.evaluate_result_exception(rpsl, expected_exception)

    def test_more_depth_2(self):
        rpsl = "AS1 AND (AS2 OR (AS3 AND AS4)) AND NOT AS5 AND (AS6 OR AS7)"
        expected_exception = (errors.UnimplementedError,
                              r"More depth .* can handle")
        self.evaluate_result_exception(rpsl, expected_exception)

    def test_absent_OR_1(self):
        rpsl = "AS1 (AS2 AND AS3) NOT AS6 (AS4 AND AS5)"
        expected_result = [
                            (True, sorted(['AS2', 'AS3'])),
                            (True, sorted(['AS1'])),
                            (True, sorted(['AS4', 'AS5'])),
                            (False, sorted(['AS6'])),
                          ]
        self.evaluate_result(rpsl, expected_result)

    def test_absent_OR_2(self):
        rpsl = "(AS0 AS1) AND (AS2 AS3) AND (AS4 AS5)"
        expected_result = [
                            (True, sorted(['AS1', 'AS3', 'AS5'])),
                            (True, sorted(['AS1', 'AS3', 'AS4'])),
                            (True, sorted(['AS0', 'AS3', 'AS5'])),
                            (True, sorted(['AS0', 'AS3', 'AS4'])),
                            (True, sorted(['AS1', 'AS2', 'AS5'])),
                            (True, sorted(['AS1', 'AS2', 'AS4'])),
                            (True, sorted(['AS0', 'AS2', 'AS5'])),
                            (True, sorted(['AS0', 'AS2', 'AS4'])),
                          ]
        self.evaluate_result(rpsl, expected_result)


if __name__ == "__main__":
    suite = unittest.TestSuite()
    suite.addTests([
        unittest.TestLoader().loadTestsFromTestCase(
            FilterSyntaxTestCase
        ),
        unittest.TestLoader().loadTestsFromTestCase(
            RPSLObjectsParseTestCase
        ),
        unittest.TestLoader().loadTestsFromTestCase(
            OperationsTestCase
        ),
    ])
    unittest.TextTestRunner(verbosity=1).run(suite)
