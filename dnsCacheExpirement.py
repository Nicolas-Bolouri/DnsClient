import sys
import time
import matplotlib.pyplot as plt
from dnsClient import DNSClient

# DNS server and records to test
dns_server = '8.8.8.8'
records = ['www.google.com', 'www.mcgill.ca', 'www.microsoft.com']
results = {'uncached': [], 'cached': []}

def query_dns(record, cache=False):
    try:
        # Instantiate the DNSClient with default options
        client = DNSClient(server=dns_server, name=record, query_type='A', timeout=5, max_retries=3, port=53)
        
        start_time = time.time()
        client.send_query()  # Sends the DNS query
        end_time = time.time()
        
        response_time = end_time - start_time
        print(f"{'Cached' if cache else 'Uncached'} response time for {record}: {response_time:.4f} seconds")
        return response_time
    except Exception as e:
        print(f"Error querying {record}: {e}")
        return None

# Test each record twice: once uncached and once cached
for record in records:
    print(f"\nQuerying DNS record for {record} (Uncached)")
    results['uncached'].append(query_dns(record, cache=False))

print("\nWaiting for 2 seconds before querying cached results...\n")
time.sleep(2)

for record in records:
    print(f"\nQuerying DNS record for {record} (Cached)")
    results['cached'].append(query_dns(record, cache=True))

# Plotting results
labels = records
uncached_times = results['uncached']
cached_times = results['cached']
x = range(len(records))

fig, ax = plt.subplots()
bar_width = 0.35

bars1 = ax.bar([pos - bar_width/2 for pos in x], uncached_times, bar_width, label='Uncached', color='skyblue')
bars2 = ax.bar([pos + bar_width/2 for pos in x], cached_times, bar_width, label='Cached', color='salmon')

ax.set_xlabel('DNS Record')
ax.set_ylabel('Response Time (s)')
ax.set_title('Cached vs Uncached DNS Response Times')
ax.set_xticks(x)
ax.set_xticklabels(labels)
ax.legend()

plt.show()
