# DNS Client

## Overview

This project implements a DNS client in Python. The client allows users to query DNS servers for various types of records (A, MX, NS) and handles responses, including retries for timeout scenarios.

## Usage

### Syntax

```bash
python dnsClient.py [-t timeout] [-r max-retries] [-p port] [-mx|-ns] @server name
```

### Arguments

- `timeout` (optional): Timeout in seconds before retransmitting an unanswered query. Default is 5 seconds.
- `max-retries` (optional): Maximum number of retries for unanswered queries. Default is 3 retries.
- `port` (optional): The UDP port of the DNS server. Default is 53.
- `-mx` or `-ns` (optional): Queries for MX (mail server) or NS (name server) records. If neither is provided, the default is an A (IP address) query.
- `server` (required): The IPv4 address of the DNS server, in a.b.c.d format.
- `name` (required): The domain name to query for.

### Example Usage

Query for the A record of `www.mcgill.ca` using Google’s public DNS server:

```bash
python dnsClient.py @8.8.8.8 www.mcgill.ca
```

Query for the MX record of `mcgill.ca` using Google’s public DNS server:

```bash
python dnsClient.py -mx @8.8.8.8 mcgill.ca
```

Query for the NS record of `mcgill.ca` with a timeout of 10 seconds and maximum retries set to 2:

```bash
python dnsClient.py -t 10 -r 2 -ns @8.8.8.8 mcgill.ca
```

### Output

The DNS client will output the request sent, server queried, and the type of request. The response includes:

- Time taken to receive a response.
- Records returned in the Answer Section.
- Any additional records if present (A, CNAME, MX, NS).

If no records are found, the client will print `NOTFOUND`. If errors occur (invalid arguments, timeouts), appropriate error messages are printed.

### Sample Output

```text
DnsClient sending request for www.mcgill.ca
Server: 8.8.8.8
Request type: A

Response received after 0.03 seconds (0 retries)

***Answer Section (1 records)***

IP     132.206.6.95    300     auth
```

## Testing

### Running Unit Tests

Unit tests for the DNS client are provided to verify its functionality, using the **unittest** framework.

To run the tests:

```bash
python dnsClient.spec.py
```

The tests will check for various scenarios, including:

- Successful A, MX, and NS record queries.
- Handling of invalid server IPs and nonexistent domains.
- Correct behavior when the maximum number of retries is exceeded.
- CNAME record handling.

### Sample Output

```text
$ python dnsClient.spec.py
.........
----------------------------------------------------------------------
Ran 9 tests in 3.561s

OK
```

## Python Version Used

Python 3.11.7 (version 3.8+ required)
