#!/usr/bin/env python3
import sys
import ipaddress
import radix

# --- Configuration ---
# Minimum allowed prefix length for IPv4. Prefixes broader than this (e.g., /7 if set to 8)
# will be "reduced" to this length by generating subnets at this length.
# This ensures that no "too general" routes defeat split-tunneling.
MIN_PREFIX_LEN_IPV4 = 8

# Minimum allowed prefix length for IPv6.
# Prefixes broader than this will be "reduced" to this length.
MIN_PREFIX_LEN_IPV6 = 16 # A common allocation size, preventing overly broad IPv6 routes.
# --- End Configuration ---

def aggregate_networks(networks, limit):
    tree = radix.Radix()
    for net_str in networks:
        try:
            net = ipaddress.ip_network(net_str.strip())
            
            # Determine the target MIN_PREFIX_LEN for this IP version
            min_prefix_len_threshold = MIN_PREFIX_LEN_IPV4 if net.version == 4 else MIN_PREFIX_LEN_IPV6

            # If the input network is broader than the threshold, "reduce" it
            if net.prefixlen < min_prefix_len_threshold:
                # Generate subnets at the threshold length and add them
                for sub_net in net.subnets(new_prefix=min_prefix_len_threshold):
                    tree.add(str(sub_net))
            else:
                # If it's already at or more specific than the threshold, add it directly
                tree.add(str(net))
            
        except (ValueError, TypeError):
            continue

    # After initial processing and potential reduction, get the collapsed list.
    aggregated = tree.prefixes()
    
    # The summarization loop for reducing count to 'limit'
    if limit > 0:
        while len(aggregated) > limit:
            summarized_tree = radix.Radix()
            
            # Use ipaddress objects for convenient manipulation
            current_nets = (ipaddress.ip_network(p) for p in aggregated)

            for net in current_nets:
                # Determine the target MIN_PREFIX_LEN for this IP version
                min_prefix_len_threshold = MIN_PREFIX_LEN_IPV4 if net.version == 4 else MIN_PREFIX_LEN_IPV6

                # Only summarize if it's possible and won't make it too broad
                if net.prefixlen > min_prefix_len_threshold:
                    summarized_tree.add(str(net.supernet()))
                else:
                    # If it's already at the min threshold or too broad to summarize,
                    # add it as is (cannot go broader than min_prefix_len_threshold)
                    summarized_tree.add(str(net))
            
            # Get the newly summarized and collapsed prefixes
            aggregated = summarized_tree.prefixes()
            
            # If no prefixes are left after summarization (e.g., all were filtered)
            # and limit is still > 0, break to prevent infinite loop.
            if not aggregated and limit > 0:
                break
    
    return aggregated

if __name__ == "__main__":
    if len(sys.argv) < 3:
        sys.stderr.write("Usage: cat ips.txt | ./aggregate.py <limit> <output_file>\n")
        sys.exit(1)

    try:
        limit = int(sys.argv[1]) if sys.argv[1] != '0' else 0
    except (ValueError, IndexError):
        limit = 0

    output_file = sys.argv[2]

    lines = sys.stdin.readlines()
    
    ipv4_nets_raw = [l for l in lines if ':' not in l]
    ipv6_nets_raw = [l for l in lines if ':' in l]

    try:
        with open(output_file, "w") as f_out:
            if ipv4_nets_raw:
                final_ipv4 = aggregate_networks(ipv4_nets_raw, limit)
                for net in final_ipv4:
                    f_out.write(net + "\n")
            
            if ipv6_nets_raw:
                final_ipv6 = aggregate_networks(ipv6_nets_raw, limit)
                for net in final_ipv6:
                    f_out.write(net + "\n")

    except IOError as e:
        sys.stderr.write(f"Error writing to file {output_file}: {e}\n")
        sys.exit(1)
    except NameError:
        sys.stderr.write("Error: 'py-radix' library not found.\n")
        sys.stderr.write("Please rebuild the Docker image or install it via: pip install py-radix\n")
        sys.exit(1)
