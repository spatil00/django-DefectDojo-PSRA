from django.test import TestCase
from dojo.tools.philips_rmm_sheet.parser import PhilipsRMMSheetParser
from dojo.models import Test


class TestPhilipsRMMSheetParser(TestCase):

    def test_philips_rmm_sheet_parser_with_no_vuln_has_no_findings(self):
        testfile = open("unittests/scans/philips_rmm_sheet/philips_rmm_sheet_zero_vul.csv")
        parser = PhilipsRMMSheetParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(0, len(findings))

    def test_philips_rmm_sheet_parser_with_one_criticle_vuln_has_one_findings(self):
        testfile = open("unittests/scans/philips_rmm_sheet/philips_rmm_sheet_one_vul.csv")
        parser = PhilipsRMMSheetParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        self.assertEqual(1, len(findings))
        self.assertEqual("handlebars", findings[0].component_name)
        self.assertEqual("4.5.2", findings[0].component_version)

    def test_philips_rmm_sheet_parser_with_many_vuln_has_many_findings(self):
        testfile = open("unittests/scans/philips_rmm_sheet/philips_rmm_sheet_many_vul.csv")
        parser = PhilipsRMMSheetParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        self.assertEqual(3, len(findings))

    def test_philips_rmm_sheet_parser_empty_with_error(self):
        with self.assertRaises(ValueError) as context:
            testfile = open("unittests/scans/philips_rmm_sheet/empty_with_error.csv")
            parser = PhilipsRMMSheetParser()
            findings = parser.get_findings(testfile, Test())
            testfile.close()
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertTrue(
                "Philips RMM Sheet report contains errors:" in str(context.exception)
            )
            self.assertTrue("ECONNREFUSED" in str(context.exception))
