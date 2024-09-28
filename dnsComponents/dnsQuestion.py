import struct

class DNSQuestion:
    def __init__(self, qname, qtype_str):
        self.qname = qname
        self.qtype = self.qtype_str_to_int(qtype_str)
        self.qclass = 1  # IN (Internet)

    def pack(self):
        """
        Packs the DNS question into bytes suitable for sending in a DNS query.
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
        Class method to create a DNSQuestion instance.
        """
        return cls(qname, qtype_str)

    @classmethod
    def unpack(cls, data, offset):
        """
        Unpacks the question section from the data starting at the given offset.
        Returns a DNSQuestion instance and the new offset.
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
        Parses the QNAME from the data starting at the given offset.
        Returns the domain name and the new offset.
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
        Converts a QTYPE integer value to its corresponding string.
        """
        qtype_map = {
            1: 'A',
            2: 'NS',
            15: 'MX'
        }
        return qtype_map.get(qtype_int, 'UNKNOWN')

    def __str__(self):
        return f"QNAME: {self.qname}, QTYPE: {self.qtype}, QCLASS: {self.qclass}"
