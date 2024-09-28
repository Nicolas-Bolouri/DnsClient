import random
import struct

class DNSHeader:
    """
    Represents the header of a DNS packet.
    
    The DNS header contains general information about the DNS query/response,
    including flags, transaction ID, and counts of questions, answers, authority,
    and additional records.
    """

    def __init__(self, flags, qd_count=1, an_count=0, ns_count=0, ar_count=0, trans_id=None):
        """
        Initializes the DNSHeader object.
        
        Args:
            flags (DNSFlags): The DNSFlags object representing various DNS flags.
            qd_count (int): The number of entries in the question section (default is 1).
            an_count (int): The number of resource records in the answer section (default is 0).
            ns_count (int): The number of name server records in the authority section (default is 0 - program essentially ignores this).
            ar_count (int): The number of resource records in the additional section (default is 0).
            trans_id (int): The transaction ID, a random 16-bit identifier. If None, a random ID is generated.
        """
        self.trans_id = trans_id if trans_id is not None else random.getrandbits(16)
        self.flags = flags  # DNSFlags object
        self.qd_count = qd_count
        self.an_count = an_count
        self.ns_count = ns_count
        self.ar_count = ar_count

    def pack(self):
        """
        Packs the DNS header into a binary format suitable for sending in a DNS packet.
        
        Returns:
            bytes: The packed binary representation of the DNS header.
        """
        return struct.pack('!HHHHHH',
                           self.trans_id,
                           self.flags.to_int(),
                           self.qd_count,
                           self.an_count,
                           self.ns_count,
                           self.ar_count)

    @classmethod
    def create_query_header(cls, flags):
        """
        Creates a new DNSHeader instance for a DNS query.
        
        Args:
            flags (DNSFlags): The DNSFlags object representing the query flags.
            
        Returns:
            DNSHeader: The created DNSHeader instance.
        """
        return cls(flags)

    @classmethod
    def unpack(cls, data):
        """
        Unpacks a binary DNS header into a DNSHeader object.
        
        Args:
            data (bytes): The binary data to unpack.
            
        Returns:
            DNSHeader: The unpacked DNSHeader object.
            
        Raises:
            ValueError: If the input data is too short to unpack.
        """
        if len(data) < 12:
            raise ValueError("Data too short to unpack DNS header")
        trans_id, flags_int, qd_count, an_count, ns_count, ar_count = struct.unpack('!HHHHHH', data[:12])
        flags = DNSFlags.from_int(flags_int)
        return cls(flags, qd_count, an_count, ns_count, ar_count, trans_id)

    def __str__(self):
        """
        Returns a string representation of the DNSHeader.
        
        Returns:
            str: The string representation of the DNSHeader.
        """
        return (f"Transaction ID: {self.trans_id}, Flags: {self.flags}, "
                f"QDCOUNT: {self.qd_count}, ANCOUNT: {self.an_count}, "
                f"NSCOUNT: {self.ns_count}, ARCOUNT: {self.ar_count}")


class DNSFlags:
    """
    Represents the DNS flags used in a DNS packet.
    
    The flags are used to indicate the type of DNS operation (query/response),
    recursion desired, recursion available, authoritative answers, and more.
    """

    def __init__(self, qr=0, opcode=0, aa=0, tc=0, rd=1, ra=0, z=0, rcode=0):
        """
        Initializes the DNSFlags object.
        
        Args:
            qr (int): Query/Response flag (0 for query, 1 for response).
            opcode (int): Operation code (default is 0 for standard query).
            aa (int): Authoritative Answer flag.
            tc (int): Truncated flag.
            rd (int): Recursion Desired flag (default is 1).
            ra (int): Recursion Available flag.
            z (int): Reserved field, must be 0.
            rcode (int): Response code (e.g., 0 for no error).
        """
        self.qr = qr        
        self.opcode = opcode  
        self.aa = aa        
        self.tc = tc       
        self.rd = rd        
        self.ra = ra        
        self.z = z         
        self.rcode = rcode 

    def to_int(self):
        """
        Converts the DNSFlags object to its integer representation.
        
        Returns:
            int: The integer value representing the DNS flags.
        """
        flags = (self.qr << 15) | (self.opcode << 11) | (self.aa << 10) | \
                (self.tc << 9) | (self.rd << 8) | (self.ra << 7) | \
                (self.z << 4) | self.rcode
        return flags

    @classmethod
    def default_query_flags(cls, tc=0):
        """
        Creates a default set of DNS flags for a query.
        
        Args:
            tc (int): Truncated flag (default is 0).
            
        Returns:
            DNSFlags: The created DNSFlags instance.
        """
        return cls(qr=0, opcode=0, aa=0, tc=tc, rd=1, ra=0, z=0, rcode=0)

    @classmethod
    def from_int(cls, flags_int):
        """
        Creates a DNSFlags object from an integer representation.
        
        Args:
            flags_int (int): The integer representation of the DNS flags.
            
        Returns:
            DNSFlags: The unpacked DNSFlags object.
        """
        qr = (flags_int >> 15) & 0x1
        opcode = (flags_int >> 11) & 0xF
        aa = (flags_int >> 10) & 0x1
        tc = (flags_int >> 9) & 0x1
        rd = (flags_int >> 8) & 0x1
        ra = (flags_int >> 7) & 0x1
        z = (flags_int >> 4) & 0x7
        rcode = flags_int & 0xF
        return cls(qr, opcode, aa, tc, rd, ra, z, rcode)

    def __str__(self):
        """
        Returns a string representation of the DNSFlags.
        
        Returns:
            str: The string representation of the DNSFlags.
        """
        return (f"QR: {self.qr}, OPCODE: {self.opcode}, AA: {self.aa}, "
                f"TC: {self.tc}, RD: {self.rd}, RA: {self.ra}, Z: {self.z}, "
                f"RCODE: {self.rcode}")
