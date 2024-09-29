import unittest
import subprocess
import sys
import os

class TestDNSClient(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not os.path.isfile('dnsClient.py'):
            print("dnsClient.py not found in the current directory.")
            sys.exit(1)

    def run_dns_client(self, args):
        """
        Runs dnsClient.py with the given arguments and returns the output.
        """
        command = [sys.executable, 'dnsClient.py'] + args
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=15)
        output = result.stdout.strip()
        return output

    def check_output(self, output, expected_patterns):
        """
        Checks if all expected patterns are present in the output.
        """
        for pattern in expected_patterns:
            with self.subTest(pattern=pattern):
                self.assertRegex(output, pattern, f"Expected pattern not found: {pattern}")

    def test_a_record(self):
        """
        Tests that an A record for 'www.google.com' can be successfully resolved using Google's DNS server.
        Verifies that the output contains information about the A record and IP address.
        """
        args = ['@8.8.8.8', 'www.google.com']
        expected_patterns = [
            r"DnsClient sending request for www\.google\.com",
            r"Server: 8\.8\.8\.8",
            r"Request type: A",
            r"Response received after [\d\.]+ seconds \(\d+ retries\)",
            r"\*\*\*Answer Section \(\d+ records\)\*\*\*",
            r"IP\t\d{1,3}(\.\d{1,3}){3}\t\d+\t(auth|nonauth)"
        ]
        output = self.run_dns_client(args)
        self.check_output(output, expected_patterns)

    def test_mx_record(self):
        """
        Tests that an MX record for 'mcgill.ca' can be successfully resolved using Google's DNS server.
        Verifies that the output contains MX record details, including mail exchange and preference.
        """
        args = ['-mx', '@8.8.8.8', 'mcgill.ca']
        expected_patterns = [
            r"DnsClient sending request for mcgill\.ca",
            r"Server: 8\.8\.8\.8",
            r"Request type: MX",
            r"Response received after [\d\.]+ seconds \(\d+ retries\)",
            r"\*\*\*Answer Section \(\d+ records\)\*\*\*",
            r"MX\t.+\t\d+\t\d+\t(auth|nonauth)"
        ]
        output = self.run_dns_client(args)
        self.check_output(output, expected_patterns)

    def test_ns_record(self):
        """
        Tests that an NS record for 'mcgill.ca' can be successfully resolved with a timeout and retries using Google's DNS server.
        Verifies that the output contains NS record details, including the name server.
        """
        args = ['-t', '10', '-r', '2', '-ns', '@8.8.8.8', 'mcgill.ca']
        expected_patterns = [
            r"DnsClient sending request for mcgill\.ca",
            r"Server: 8\.8\.8\.8",
            r"Request type: NS",
            r"Response received after [\d\.]+ seconds \(\d+ retries\)",
            r"\*\*\*Answer Section \(\d+ records\)\*\*\*",
            r"NS\t.+\t\d+\t(auth|nonauth)"
        ]
        output = self.run_dns_client(args)
        self.check_output(output, expected_patterns)

    def test_invalid_server_ip(self):
        """
        Tests the DNS client with an invalid server IP address.
        Verifies that an error message is displayed indicating the invalid IP format.
        """
        args = ['@999.999.999.999', 'www.google.com']
        expected_patterns = [
            r"ERROR\tInvalid DNS server provided\. IPv4 octets must be between 0 and 255\."
        ]
        output = self.run_dns_client(args)
        self.check_output(output, expected_patterns)

    def test_nonexistent_domain(self):
        """
        Tests resolving a nonexistent domain 'nonexistentdomain.example' using Google's DNS server.
        Verifies that the DNS client returns a NOTFOUND message.
        """
        args = ['@8.8.8.8', 'nonexistentdomain.example']
        expected_patterns = [
            r"DnsClient sending request for nonexistentdomain\.example",
            r"Server: 8\.8\.8\.8",
            r"Request type: A",
            r"Response received after [\d\.]+ seconds \(\d+ retries\)",
            r"NOTFOUND"
        ]
        output = self.run_dns_client(args)
        self.check_output(output, expected_patterns)

    def test_max_retries_exceeded(self):
        """
        Tests the DNS client with a server that does not respond (0.0.0.0) and checks that retries are handled correctly.
        Verifies that after maximum retries, an appropriate error message is displayed.
        """
        args = ['-t', '1', '-r', '2', '@0.0.0.0', 'www.google.com']
        expected_patterns = [
            r"DnsClient sending request for www\.google\.com",
            r"Server: 0\.0\.0\.0",
            r"Request type: A",
            r"ERROR\tTimeout occurred, retrying\.\.\. \(\d+/\d+\)",
            r"ERROR\tMaximum number of retries 2 exceeded"
        ]
        output = self.run_dns_client(args)
        self.check_output(output, expected_patterns)

    def test_invalid_arguments(self):
        """
        Tests the DNS client with invalid arguments.
        Verifies that an appropriate error message is displayed indicating unexpected argument.
        """
        args = ['-invalid', '@8.8.8.8', 'www.google.com']
        expected_patterns = [
            r"ERROR\tUnexpected argument: -invalid"
        ]
        output = self.run_dns_client(args)
        self.check_output(output, expected_patterns)

    def test_missing_server_or_name(self):
        """
        Tests the DNS client with missing server or domain name arguments.
        Verifies that an appropriate error message is displayed indicating missing input.
        """
        args = ['@8.8.8.8']
        expected_patterns = [
            r"ERROR\tIncorrect input syntax: Missing server or name"
        ]
        output = self.run_dns_client(args)
        self.check_output(output, expected_patterns)

    def test_cname_record(self):
        """
        Tests that a CNAME record for 'www.microsoft.com' can be successfully resolved using Google's DNS server.
        Verifies that the output contains the CNAME record and alias information.
        """
        args = ['@8.8.8.8', 'www.microsoft.com']
        expected_patterns = [
            r"DnsClient sending request for www\.microsoft\.com",
            r"Server: 8\.8\.8\.8",
            r"Request type: A",
            r"Response received after [\d\.]+ seconds \(\d+ retries\)",
            r"\*\*\*Answer Section \(\d+ records\)\*\*\*",
            r"CNAME\t.+\t\d+\t(auth|nonauth)"
        ]
        output = self.run_dns_client(args)
        self.check_output(output, expected_patterns)

    def test_additional_section(self):
        """
        Tests that additional sections of a DNS response are correctly parsed and displayed.
        Verifies that the output contains the details from the additional section if present.
        """
        args = ['@8.8.8.8', 'mcgill.ca']  
        output = self.run_dns_client(args)

        if "***Additional Section" in output:
            expected_patterns = [
                r"\*\*\*Additional Section \(\d+ records\)\*\*\*",
                r"IP\t\d{1,3}(\.\d{1,3}){3}\t\d+\t(auth|nonauth)"
            ]
        else:
            expected_patterns = [
                r"DnsClient sending request for mcgill\.ca",
                r"Server: 8\.8\.8\.8",
                r"Request type: A",
                r"Response received after [\d\.]+ seconds \(\d+ retries\)",
            ]
        
        self.check_output(output, expected_patterns)

    def test_rcode_handling(self):
        """
        Tests the DNS client for various RCODE values in the response.
        Verifies that the client displays appropriate error messages for different RCODE values.
        """
        args = ['@8.8.8.8', 'nonexistentdomain.example']
        expected_patterns = [
            r"NOTFOUND"  # Triggering RCODE 3: Name Error
        ]
        output = self.run_dns_client(args)
        self.check_output(output, expected_patterns)

if __name__ == '__main__':
    unittest.main()