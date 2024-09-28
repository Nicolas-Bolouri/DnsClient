import struct
import socket

class DNSAnswer:
    """
    Represents a DNS answer resource record in a DNS response.
    
    This class handles the parsing and string representation of DNS resource records 
    such as A, NS, CNAME, and MX records.
    """

    def __init__(self, name, rr_type, rr_class, ttl, rdlength, rdata):
        """
        Initializes the DNSAnswer object.
        
        Args:
            name (str): The domain name for which the answer is provided.
            rr_type (int): The resource record type (e.g., 1 for A record, 2 for NS, etc.).
            rr_class (int): The resource record class (e.g., 1 for IN (Internet)).
            ttl (int): The time-to-live (TTL) value for this resource record.
            rdlength (int): The length of the RDATA field.
            rdata (str or tuple): The RDATA, which depends on the rr_type. It can be an IP address (A), 
                                  domain name (NS, CNAME), or a tuple (preference, exchange) for MX records.
        """
        self.name = name        
        self.rr_type = rr_type  
        self.rr_class = rr_class 
        self.ttl = ttl          
        self.rdlength = rdlength  
        self.rdata = rdata     

    def __str__(self, auth_bit=None):
        """
        Returns a string representation of the DNSAnswer object, including whether the 
        response is authoritative or non-authoritative.
        
        Args:
            auth_bit (int, optional): A flag indicating whether the response is authoritative (1) or not (0).
        
        Returns:
            str: A formatted string representing the DNS answer record.
        """
        auth = "nonauth"
        if auth_bit == 1:
            auth = "auth"

        if self.rr_type == 1:  # A record
            return f"IP\t{self.rdata}\t{self.ttl}\t{auth}"
        elif self.rr_type == 2:  # NS record
            return f"NS\t{self.rdata}\t{self.ttl}\t{auth}"
        elif self.rr_type == 5:  # CNAME record
            return f"CNAME\t{self.rdata}\t{self.ttl}\t{auth}"
        elif self.rr_type == 15:  # MX record
            preference, exchange = self.rdata
            return f"MX\t{exchange}\t{preference}\t{self.ttl}\t{auth}"
        else:
            return f"TYPE {self.rr_type}\tData: {self.rdata}\t{self.ttl}\t{auth}"

    @classmethod
    def unpack(cls, data, offset):
        """
        Unpacks a resource record from the binary data starting at the given offset.
        
        Args:
            data (bytes): The binary data from the DNS response.
            offset (int): The current offset in the data where the resource record starts.
        
        Returns:
            tuple: A tuple containing the unpacked DNSAnswer instance and the new offset after reading the resource record.
        
        Raises:
            ValueError: If the data is insufficient to unpack the resource record or its RDATA field.
        """
        name, offset = cls.parse_name(data, offset)

        if offset + 10 > len(data):
            raise ValueError("Insufficient data to unpack resource record header")

        rr_type, rr_class, ttl, rdlength = struct.unpack('!HHIH', data[offset:offset+10])
        offset += 10

        if offset + rdlength > len(data):
            raise ValueError("RDLENGTH exceeds data size")

        rdata_raw = data[offset:offset+rdlength]
        rdata_offset = offset 
        offset += rdlength

        # Parse RDATA based on TYPE
        if rr_type == 1:  # A record
            if rdlength != 4:
                raise ValueError("Invalid RDLENGTH for A record")
            ip_address = socket.inet_ntoa(rdata_raw)
            rdata = ip_address
        elif rr_type == 2 or rr_type == 5:  # NS or CNAME record
            rdata, _ = cls.parse_name(data, rdata_offset)
        elif rr_type == 15:  # MX record
            if rdlength < 3:
                raise ValueError("Invalid RDLENGTH for MX record")
            preference = struct.unpack('!H', rdata_raw[:2])[0]
            exchange, _ = cls.parse_name(data, rdata_offset + 2)
            rdata = (preference, exchange)
        else:
            rdata = rdata_raw

        return cls(name, rr_type, rr_class, ttl, rdlength, rdata), offset

    @staticmethod
    def parse_name(data, offset):
        """
        Parses a domain name (QNAME) from the binary data starting at the given offset.
        This method also handles DNS name compression.
        
        Args:
            data (bytes): The binary data from the DNS response.
            offset (int): The current offset in the data where the domain name starts.
        
        Returns:
            tuple: A tuple containing the parsed domain name and the new offset after reading the name.
        
        Raises:
            ValueError: If the data is insufficient to parse the name or if the offset exceeds the data length.
        """
        labels = []
        original_offset = offset
        jumped = False
        while True:
            if offset >= len(data):
                raise ValueError("Offset out of bounds while parsing name")
            length = data[offset]
            if length == 0:
                offset += 1
                break
            elif length & 0xC0 == 0xC0:
                # Pointer to another part of the message (name compression)
                if not jumped:
                    original_offset = offset + 2
                    jumped = True
                pointer = ((length & 0x3F) << 8) | data[offset + 1]
                offset = pointer
            else:
                offset += 1
                label = data[offset:offset + length].decode('ascii')
                labels.append(label)
                offset += length
        if not jumped:
            return '.'.join(labels), offset
        else:
            return '.'.join(labels), original_offset
