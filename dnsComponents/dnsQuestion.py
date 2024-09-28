import struct

class DNSQuestion:
    """
    Represents a DNS question section in a DNS query or response.
    
    The DNS question specifies the domain name (QNAME), the type of query (QTYPE),
    and the class of the query (QCLASS), which is typically 1 for Internet (IN).
    """
    
    def __init__(self, qname, qtype_str):
        """
        Initializes a DNSQuestion object with the specified domain name (QNAME) and query type (QTYPE).
        
        Args:
            qname (str): The domain name being queried.
            qtype_str (str): The type of query, e.g., 'A', 'NS', or 'MX'.
        """
        self.qname = qname
        self.qtype = self.qtype_str_to_int(qtype_str)
        self.qclass = 1  # IN (Internet)

    def pack(self):
        """
        Packs the DNS question into bytes suitable for sending in a DNS query.
        
        The question is encoded as the QNAME (labels separated by dots and prefixed with their length), 
        followed by the QTYPE and QCLASS fields.
        
        Returns:
            bytes: The packed binary representation of the DNS question.
        """
        qname_encoded = b''
        for label in self.qname.split('.'):
            length = len(label)
            qname_encoded += struct.pack('!B', length)
            qname_encoded += label.encode('ascii')
        qname_encoded += b'\x00'  # Terminate with a zero-length label

        qtype_class = struct.pack('!HH', self.qtype, self.qclass)

        return qname_encoded + qtype_class

    @staticmethod
    def qtype_str_to_int(qtype_str):
        """
        Converts a QTYPE string to its corresponding integer value.
        
        Args:
            qtype_str (str): The query type as a string, e.g., 'A', 'NS', 'MX'.
            
        Returns:
            int: The corresponding integer value for the query type.
        """
        qtype_map = {
            'A': 1,
            'NS': 2,
            'MX': 15
        }
        return qtype_map.get(qtype_str.upper(), 1)  # Default to type A if not found

    @classmethod
    def create_question(cls, qname, qtype_str):
        """
        Class method to create a DNSQuestion instance with a given domain name and query type.
        
        Args:
            qname (str): The domain name to query.
            qtype_str (str): The type of query, e.g., 'A', 'NS', 'MX'.
            
        Returns:
            DNSQuestion: The created DNSQuestion instance.
        """
        return cls(qname, qtype_str)

    @classmethod
    def unpack(cls, data, offset):
        """
        Unpacks the question section from the binary data starting at the given offset.
        
        Args:
            data (bytes): The binary DNS message containing the question section.
            offset (int): The offset at which to start unpacking the question.
            
        Returns:
            tuple: A tuple containing the DNSQuestion instance and the new offset.
            
        Raises:
            ValueError: If there is insufficient data to unpack the question or the QTYPE/QCLASS.
        """
        qname, offset = cls.parse_qname(data, offset)

        if offset + 4 > len(data):
            raise ValueError("Insufficient data to unpack QTYPE and QCLASS")

        qtype, _ = struct.unpack('!HH', data[offset:offset + 4])
        offset += 4

        qtype_str = cls.qtype_int_to_str(qtype)

        # Create and return DNSQuestion instance
        return cls(qname, qtype_str), offset

    @staticmethod
    def parse_qname(data, offset):
        """
        Parses the QNAME (domain name) from the binary data starting at the given offset.
        
        Handles DNS name compression if necessary and constructs the full domain name.
        
        Args:
            data (bytes): The binary data containing the QNAME.
            offset (int): The offset in the data where the QNAME starts.
        
        Returns:
            tuple: A tuple containing the parsed domain name (str) and the new offset.
        
        Raises:
            ValueError: If the data is malformed or incomplete during parsing.
        """
        labels = []
        while True:
            if offset >= len(data):
                raise ValueError("Reached end of data while parsing QNAME")
            length = data[offset]
            if length == 0:
                offset += 1  # Move past the null byte
                break
            else:
                offset += 1
                if offset + length > len(data):
                    raise ValueError("Length exceeds data size while parsing label")
                label = data[offset:offset + length].decode('ascii')
                labels.append(label)
                offset += length
        qname = '.'.join(labels)
        return qname, offset

    @staticmethod
    def qtype_int_to_str(qtype_int):
        """
        Converts a QTYPE integer value to its corresponding string representation.
        
        Args:
            qtype_int (int): The integer value of the QTYPE, e.g., 1 for 'A', 2 for 'NS', 15 for 'MX'.
            
        Returns:
            str: The string representation of the query type, or 'UNKNOWN' if not recognized.
        """
        qtype_map = {
            1: 'A',
            2: 'NS',
            15: 'MX'
        }
        return qtype_map.get(qtype_int, 'UNKNOWN')

    def __str__(self):
        """
        Returns a string representation of the DNSQuestion instance.
        
        Returns:
            str: The string representation showing the QNAME, QTYPE, and QCLASS.
        """
        return f"QNAME: {self.qname}, QTYPE: {self.qtype}, QCLASS: {self.qclass}"
