## Project Overview
This project develops a fast version of the traceroute tool optimized to send probes in parallel, significantly reducing the time required to trace routes compared to the traditional sequential method. This tool is designed to analyze the Internet's topology by identifying the route and measuring transit delays of packets across an IP network.

## Key Features
* Parallel Probing: Unlike traditional traceroute, which sends probes sequentially, this tool sends all probes simultaneously to each hop along the path to the destination. This approach minimizes the overall execution time.
* Detailed Route Information: The tool provides detailed information about each hop, including IP addresses, DNS names, and round-trip times.
* Dynamic Timeout Adjustment: Implements a dynamic algorithm to set per-hop timeouts based on the response times of adjacent hops, improving the accuracy and efficiency of the probe.
* Error Detection: Capable of recognizing and displaying different ICMP error messages from routers along the path.
* High Precision Timing: Utilizes high-resolution timing functions to measure round-trip times in microseconds, providing precise network latency measurements.

## Usage
The program is designed to be used from the command line with a single destination input. It can accept both hostnames and IP addresses as input. Usage is as follows: ```C:\> trace.exe [destination]```

**Example Output:**
```
C:\> trace.exe www.yahoo.com
Tracerouting to 66.94.230.52...
 1 dc (128.194.135.65) 0.226 ms (1)
 2 <no DNS entry> (128.194.135.62) 0.735 ms (1)
...
25 p21.www.scd.yahoo.com (66.94.230.52) 84.435 ms (1)
Total execution time: 650 ms
```

## Implementation Details
* Single-threaded Architecture: Ensures that probe sending and response handling are managed within a single thread to simplify the synchronization overhead.
* ICMP Packet Handling: Utilizes raw ICMP sockets to send echo requests and handle echo replies or TTL-expired responses from intermediate routers.
* Adaptive Timeouts: Adjusts timeouts dynamically based on the network responses to optimize performance and reduce waiting times for unresponsive hops.

## Building and Running
The tool requires administrator privileges due to the use of raw sockets. Users must ensure that ICMP traffic is not blocked by any firewalls or security settings on the host machine.

**Environment Requirements:**
* Windows with ICMP allowed through the firewall
* Administrator privileges to create raw sockets

## Potential Enhancements
* Batch Mode Operations: For large-scale analyses, a batch mode can be implemented to trace routes to multiple destinations simultaneously, reducing the network footprint and avoiding redundancy.
* Network Topology Mapping: Advanced features could include dynamic mapping of network topology to identify frequently encountered routers and optimize the tracing process to reduce unnecessary traffic.
