import socket
import time
import matplotlib.pyplot as plt

# Records to test
dns_server = '8.8.8.8'
records = ['www.google.com', 'www.mcgill.ca', 'www.microsoft.com']
results = {'uncached': [], 'cached': []}

def query_dns(record, server, cache=False):
    try:
        start_time = time.time()
        # Using the DNS library to perform a query and cache the result
        addr = socket.gethostbyname_ex(record)
        end_time = time.time()
        response_time = end_time - start_time
        print(f"{'Cached' if cache else 'Uncached'} response time for {record}: {response_time:.4f} seconds")
        return response_time
    except socket.gaierror:
        print(f"Failed to resolve {record}")
        return None

# Test each record twice: once uncached and once cached
for record in records:
    print(f"\nQuerying DNS record for {record} (Uncached)")
    results['uncached'].append(query_dns(record, dns_server, cache=False))
    
print("\nWaiting for 2 seconds before querying cached results...\n")
time.sleep(2)

for record in records:
    print(f"\nQuerying DNS record for {record} (Cached)")
    results['cached'].append(query_dns(record, dns_server, cache=True))

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
