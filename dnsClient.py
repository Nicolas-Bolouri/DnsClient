import socket
import sys
import time
import re
from dnsComponents import DNSHeader, DNSQuestion, DNSAnswer, DNSFlags

def parse_arguments(argv):
    """
    Parses the command-line arguments to configure the DNS client.
    
    Args:
        argv (list): A list of command-line arguments provided to the DNS client.
    
    Returns:
        dict: A dictionary containing the parsed options, including timeout, max retries,
              port, query type, server, and name.
              
    Raises:
        SystemExit: If the input syntax is incorrect, unexpected arguments are found, or 
                    required arguments (server or name) are missing.
    """
    options = {
        'timeout': 5,
        'max_retries': 3,
        'port': 53,
        'query_type': 'A',
        'server': None,
        'name': None
    }
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg == '-t':
            i += 1
            if i < len(argv):
                options['timeout'] = int(argv[i])
            else:
                print("ERROR\tIncorrect input syntax: Missing value for -t")
                sys.exit(1)
        elif arg == '-r':
            i += 1
            if i < len(argv):
                options['max_retries'] = int(argv[i])
            else:
                print("ERROR\tIncorrect input syntax: Missing value for -r")
                sys.exit(1)
        elif arg == '-p':
            i += 1
            if i < len(argv):
                options['port'] = int(argv[i])
            else:
                print("ERROR\tIncorrect input syntax: Missing value for -p")
                sys.exit(1)
        elif arg == '-mx':
            if options['query_type'] != 'A':
                print("ERROR\tCannot specify both -mx and -ns")
                sys.exit(1)
            options['query_type'] = 'MX'
        elif arg == '-ns':
            if options['query_type'] != 'A':
                print("ERROR\tCannot specify both -mx and -ns")
                sys.exit(1)
            options['query_type'] = 'NS'
        elif arg.startswith('@'):
            if options['server'] is not None:
                print(f"ERROR\tUnexpected argument: {arg}")
                sys.exit(1)
            options['server'] = arg[1:]
        elif options['name'] is None and not arg.startswith('-'):
            options['name'] = arg
        else:
            print(f"ERROR\tUnexpected argument: {arg}")
            sys.exit(1)
        i += 1

    if options['server'] is None or options['name'] is None:
        print("ERROR\tIncorrect input syntax: Missing server or name")
        sys.exit(1)

    return options

class DNSClient:
    """
    Represents a DNS client that sends DNS queries and processes responses.
    
    Attributes:
        server (str): The IP address of the DNS server to query.
        name (str): The domain name to resolve.
        query_type (str): The type of DNS query (e.g., 'A', 'MX', 'NS').
        timeout (int): The timeout duration in seconds for each query attempt.
        max_retries (int): The maximum number of retries if the query times out.
        port (int): The port number to use for the DNS query (default is 53).
    """
    
    def __init__(self, server, name, query_type='A', timeout=5, max_retries=3, port=53):
        """
        Initializes the DNSClient object with the server, name, and configuration options.
        
        Args:
            server (str): The IP address of the DNS server to query.
            name (str): The domain name to resolve.
            query_type (str): The type of DNS query (default is 'A').
            timeout (int): Timeout duration in seconds for each query attempt (default is 5).
            max_retries (int): Maximum number of retries on timeout (default is 3).
            port (int): The port number for the DNS query (default is 53).
        """
        self.server = server
        self.name = name
        self.query_type = query_type
        self.timeout = timeout
        self.max_retries = max_retries
        self.port = port

    def send_query(self):
        """
        Sends a DNS query to the server and handles the response, retrying on timeout.
        
        Raises:
            socket.timeout: If the server does not respond within the timeout duration.
            Exception: If any other error occurs while sending or receiving the DNS query.
        """
        retries = 0
        response_received = False

        while not response_received and retries <= self.max_retries:
            try:
                # Create a UDP socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(self.timeout)

                # Build the DNS query
                flags = DNSFlags.default_query_flags()
                header = DNSHeader(flags=flags)
                question = DNSQuestion.create_question(self.name, self.query_type)
                dns_query = header.pack() + question.pack()

                print(f"DnsClient sending request for {self.name}")
                print(f"Server: {self.server}")
                print(f"Request type: {self.query_type}\n")

                start_time = time.time()
                sock.sendto(dns_query, (self.server, self.port))

                # Receive the response
                data, _ = sock.recvfrom(512)
                end_time = time.time()
                response_time = end_time - start_time

                print(f"Response received after {response_time:.3f} seconds ({retries} retries)\n")

                # Parse the response
                self.parse_response(data, header)

                response_received = True

            except socket.timeout:
                retries += 1
                if retries > self.max_retries:
                    print(f"ERROR\tMaximum number of retries {self.max_retries} exceeded")
                    break
                else:
                    print(f"ERROR\tTimeout occurred, retrying... ({retries}/{self.max_retries})")
            except Exception as e:
                print(f"ERROR\t{e}")
                break
            finally:
                sock.close()

    def parse_response(self, data, request_header):
        """
        Parses the DNS response received from the server and checks for errors.
        
        Args:
            data (bytes): The raw DNS response data received from the server.
            request_header (DNSHeader): The DNSHeader from the original request for validation.
        
        Prints:
            The answer section, additional section, and any errors encountered during the parsing process.
        """
        header = DNSHeader.unpack(data[:12])
        flags = header.flags

        if header.trans_id != request_header.trans_id:
            print("ERROR\tUnexpected response: Request ID and Response ID do not match.")
            return

        rcode = flags.rcode
        if rcode == 1:
            print("ERROR\tFormat error: the name server was unable to interpret the query")
            return
        elif rcode == 2:
            print("ERROR\tServer failure: the name server was unable to process this query due to a problem with the name server")
            return
        elif rcode == 3:
            print("NOTFOUND")
            return
        elif rcode == 4:
            print("ERROR\tNot implemented: the name server does not support the requested kind of query")
            return
        elif rcode == 5:
            print("ERROR\tRefused: the name server refuses to perform the requested operation for policy reasons")
            return

        if flags.ra == 0:
            print("ERROR\tUnexpected response: DNS Server does not support recursive queries")

        offset = 12
        for _ in range(header.qd_count):
            _, offset = DNSQuestion.unpack(data, offset)

        # Parse answer section
        print(f"***Answer Section ({header.an_count} records)***\n")
        answers = []
        for _ in range(header.an_count):
            answer, offset = DNSAnswer.unpack(data, offset)
            answers.append(answer)

        if len(answers) == 0:
            print("NOTFOUND")
            return

        auth_bit = flags.aa
        for answer in answers:
            print(answer.__str__(auth_bit=auth_bit))

        if header.ar_count > 0:
            print(f"\n***Additional Section ({header.ar_count} records)***\n")
            for _ in range(header.ar_count):
                answer, offset = DNSAnswer.unpack(data, offset)
                print(answer.__str__(auth_bit=auth_bit))

def main():
    """
    The main entry point of the DNS client. It parses arguments, validates input, and initiates the DNS query.
    """
    options = parse_arguments(sys.argv[1:])
    server_ip = options['server']
    if not re.match(r'^\d{1,3}(\.\d{1,3}){3}$', server_ip):
        print("ERROR\tInvalid DNS server provided. The server should be a valid IPv4 address.")
        sys.exit(1)
    octets = server_ip.split('.')
    for octet in octets:
        if not 0 <= int(octet) <= 255:
            print("ERROR\tInvalid DNS server provided. IPv4 octets must be between 0 and 255.")
            sys.exit(1)

    client = DNSClient(
        server=options['server'],
        name=options['name'],
        query_type=options['query_type'],
        timeout=options['timeout'],
        max_retries=options['max_retries'],
        port=options['port']
    )
    client.send_query()

if __name__ == "__main__":
    main()
