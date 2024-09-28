import struct
import socket

class DNSAnswer:
    def __init__(self, name, rr_type, rr_class, ttl, rdlength, rdata):
        self.name = name        
        self.rr_type = rr_type  
        self.rr_class = rr_class 
        self.ttl = ttl          
        self.rdlength = rdlength  
        self.rdata = rdata     

    def __str__(self, auth_bit=None):
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
        Unpacks a resource record from the data starting at the given offset.
        Returns a DNSAnswer instance and the new offset.
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
        Parses a domain name from data starting at the given offset.
        Handles DNS name compression.
        Returns the domain name and the new offset.
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
                # Pointer to another part of the message
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
