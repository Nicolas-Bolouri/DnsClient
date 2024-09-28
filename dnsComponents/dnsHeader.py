import random
import struct

class DNSHeader:
    def __init__(self, flags, qd_count=1, an_count=0, ns_count=0, ar_count=0, trans_id=None):
        self.trans_id = trans_id if trans_id is not None else random.getrandbits(16)
        self.flags = flags  # DNSFlags object
        self.qd_count = qd_count
        self.an_count = an_count
        self.ns_count = ns_count
        self.ar_count = ar_count

    def pack(self):
        return struct.pack('!HHHHHH',
                           self.trans_id,
                           self.flags.to_int(),
                           self.qd_count,
                           self.an_count,
                           self.ns_count,
                           self.ar_count)

    @classmethod
    def create_query_header(cls, flags):
        return cls(flags)

    @classmethod
    def unpack(cls, data):
        if len(data) < 12:
            raise ValueError("Data too short to unpack DNS header")
        trans_id, flags_int, qd_count, an_count, ns_count, ar_count = struct.unpack('!HHHHHH', data[:12])
        flags = DNSFlags.from_int(flags_int)
        return cls(flags, qd_count, an_count, ns_count, ar_count, trans_id)

    def __str__(self):
        return (f"Transaction ID: {self.trans_id}, Flags: {self.flags}, "
                f"QDCOUNT: {self.qd_count}, ANCOUNT: {self.an_count}, "
                f"NSCOUNT: {self.ns_count}, ARCOUNT: {self.ar_count}")


class DNSFlags:
    def __init__(self, qr=0, opcode=0, aa=0, tc=0, rd=1, ra=0, z=0, rcode=0):
        self.qr = qr        # Query/Response flag
        self.opcode = opcode  # Operation code
        self.aa = aa        # Authoritative Answer
        self.tc = tc        # Truncated
        self.rd = rd        # Recursion Desired
        self.ra = ra        # Recursion Available
        self.z = z          # Reserved
        self.rcode = rcode  # Response Code

    def to_int(self):
        flags = (self.qr << 15) | (self.opcode << 11) | (self.aa << 10) | \
                (self.tc << 9) | (self.rd << 8) | (self.ra << 7) | \
                (self.z << 4) | self.rcode
        return flags

    @classmethod
    def default_query_flags(cls, tc=0):
        return cls(qr=0, opcode=0, aa=0, tc=tc, rd=1, ra=0, z=0, rcode=0)

    @classmethod
    def from_int(cls, flags_int):
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
        return (f"QR: {self.qr}, OPCODE: {self.opcode}, AA: {self.aa}, "
                f"TC: {self.tc}, RD: {self.rd}, RA: {self.ra}, Z: {self.z}, "
                f"RCODE: {self.rcode}")
