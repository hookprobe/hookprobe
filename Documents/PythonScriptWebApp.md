## Python Script to automate web app deployment --- TEST ONLY not read

Below is an **illustrative** Python script that demonstrates how you might:

1. **Create multiple Linux namespaces** (for web app, database, FRR, etc.).  
2. **Set up a VXLAN** interface to interconnect them.  
3. **Assign IP addresses** and bring up interfaces.  
4. **Run processes** (e.g., Django/Gunicorn, Nginx, PostgreSQL, and FRR) inside each namespace using `nsenter`.  

> **Important Notes**  
> - This script is for **educational/demonstration** purposes. It shows the general approach of using `ip netns`, `ip link`, `vxlan`, and `nsenter` to isolate network stacks and run processes.  
> - In practice, you would likely use Docker/LXC/Podman/Kubernetes or a combination of container + network tooling (like CNI plugins) to manage these steps more cleanly.  
> - This script assumes you have root privileges, because creating network namespaces and links requires elevated permissions.  
> - It also assumes that you are comfortable installing packages (e.g., FRR, PostgreSQL, Django) in the **host filesystem** and then running them inside a network namespace. If you want full filesystem isolation, you would need to combine this with `chroot`, `systemd-nspawn`, Docker, or other container runtimes.  
> - You may need to adjust IP addresses, interface names, FRR config, etc. to suit your environment.  

---

## High-Level Flow

1. **Create Namespaces**: `web-ns`, `db-ns`, `frr-ns` (you can add more if you want to replicate the diagram’s POD structure).  
2. **Create a VxLAN** in each namespace and on the host, or create veth pairs bridging the host and each namespace (depending on how you want your traffic to flow).  
3. **Assign IPs** to each interface in each namespace.  
4. **Start Services**:  
   - In `web-ns`: Nginx, Gunicorn, Django  
   - In `db-ns`: PostgreSQL  
   - In `frr-ns`: FRR (Free Range Routing)  
5. **(Optional) Add additional containers/namespaces** for your SIEM, AI engine, or other pods from the diagram.

Below is a **minimal** example that you can expand.

---

```python
#!/usr/bin/env python3
import subprocess
import os
import time

def run_cmd(cmd):
    """
    Helper to run shell commands with error checking.
    """
    print(f"[CMD] {cmd}")
    subprocess.run(cmd, shell=True, check=True)

def create_namespace(ns_name):
    """
    Create a network namespace.
    """
    run_cmd(f"ip netns add {ns_name}")

def delete_namespace(ns_name):
    """
    Delete a network namespace (cleanup).
    """
    run_cmd(f"ip netns delete {ns_name}")

def create_vxlan_in_namespace(ns_name, vxlan_name, vxlan_id, local_ip, remote_ip=None, dev="eth0"):
    """
    Create a VXLAN interface inside a namespace.  
    - vxlan_id: numeric VXLAN ID  
    - local_ip: IP used as 'local' in VXLAN  
    - remote_ip: optional IP used as 'remote' in VXLAN (for point-to-point).  
    - dev: the underlying device used by the VXLAN.  
    """
    # Move the primary interface (dev) into the namespace if needed, or create a veth to connect host <-> namespace
    # For demonstration, assume we already have an interface inside the namespace named 'eth0' with local_ip.
    #
    # The example below just shows how to create a vxlan interface. You can adapt to your environment.
    
    # Enter the namespace to run ip commands
    base_cmd = f"ip netns exec {ns_name}"
    
    # Create vxlan interface
    run_cmd(f"{base_cmd} ip link add {vxlan_name} type vxlan id {vxlan_id} dev {dev} local {local_ip}"
            + (f" remote {remote_ip}" if remote_ip else "")
            + " dstport 4789")
    
    # Bring up vxlan interface
    run_cmd(f"{base_cmd} ip link set {vxlan_name} up")

def assign_ip_address(ns_name, interface, ip_cidr):
    """
    Assign an IP address to an interface in a given namespace.
    """
    base_cmd = f"ip netns exec {ns_name}"
    run_cmd(f"{base_cmd} ip addr add {ip_cidr} dev {interface}")

def bring_interface_up(ns_name, interface):
    """
    Bring an interface up inside a given namespace.
    """
    base_cmd = f"ip netns exec {ns_name}"
    run_cmd(f"{base_cmd} ip link set {interface} up")

def run_process_in_namespace(ns_name, command):
    """
    Run a process (foreground or background) inside a given namespace using nsenter.
    By default, this example only enters the 'net' namespace, but you could also
    add --uts, --ipc, --pid, etc. for deeper isolation.
    """
    # First get the PID for a process that is "anchoring" that namespace (if needed).
    # For simplicity, we use the fact that 'ip netns exec' will spawn a shell in that netns.
    # Or you can do: `lsns -t net` to see the netns in question. Then `nsenter --net=/proc/<pid>/ns/net ...`
    #
    # If you want to do everything in one shot, you can just do:
    run_cmd(f"ip netns exec {ns_name} {command}")

def install_packages_in_namespace(ns_name, packages):
    """
    Demonstrates how you might install packages within the namespace
    (Note: This only works if the namespace shares the host's mount/filesystem + pid).
    For a real container environment, you'd typically do this differently.
    """
    pkg_str = " ".join(packages)
    run_process_in_namespace(ns_name, f"apt-get update && apt-get install -y {pkg_str}")

def main():
    # Namespaces we want
    web_ns = "web-ns"
    db_ns = "db-ns"
    frr_ns = "frr-ns"

    # 1. CREATE NAMESPACES
    for ns in [web_ns, db_ns, frr_ns]:
        create_namespace(ns)
    
    # 2. (Optional) CREATE VETH PAIRS or VXLAN to connect them
    #    For a minimal example, let's do something simpler:
    #    - We'll assign a direct IP in each namespace on a "dummy" interface or the loopback
    #    - We'll show how to create a VXLAN interface. In a real environment, you'd do more.

    # Bring up loopback in each namespace
    for ns in [web_ns, db_ns, frr_ns]:
        run_cmd(f"ip netns exec {ns} ip link set lo up")

    # Suppose each namespace is on a 10.0.x.0/24 range
    assign_ip_address(web_ns, "lo", "10.0.1.1/32")
    assign_ip_address(db_ns,  "lo", "10.0.2.1/32")
    assign_ip_address(frr_ns, "lo", "10.0.3.1/32")

    # Example of creating a VXLAN interface in each namespace (if you want to connect them):
    # Let’s pretend each namespace has an 'eth0' with a unique local IP, and they share a remote IP.
    # This is purely an example – adjust to your environment.
    create_vxlan_in_namespace(web_ns,  "vxlan0", vxlan_id=100, local_ip="10.0.1.10")
    create_vxlan_in_namespace(db_ns,   "vxlan0", vxlan_id=100, local_ip="10.0.2.10")
    create_vxlan_in_namespace(frr_ns,  "vxlan0", vxlan_id=100, local_ip="10.0.3.10")

    # Assign IP addresses to those vxlan interfaces
    assign_ip_address(web_ns,  "vxlan0", "192.168.100.1/24")
    assign_ip_address(db_ns,   "vxlan0", "192.168.100.2/24")
    assign_ip_address(frr_ns,  "vxlan0", "192.168.100.3/24")

    # Bring them up
    bring_interface_up(web_ns,  "vxlan0")
    bring_interface_up(db_ns,   "vxlan0")
    bring_interface_up(frr_ns,  "vxlan0")

    # 3. INSTALL PACKAGES (if needed) - demonstration only
    #    If your host can see the same root FS, you might do:
    # install_packages_in_namespace(web_ns, ["python3-pip", "python3-venv", "gunicorn", "nginx"])
    # install_packages_in_namespace(db_ns, ["postgresql"])
    # install_packages_in_namespace(frr_ns, ["frr"])

    # 4. RUN PROCESSES:
    #    a) PostgreSQL in db-ns
    #       - Typically you'd do: run_process_in_namespace(db_ns, "service postgresql start")
    #       - Or run the DB in the foreground with a config that listens on 10.0.2.1 or 192.168.100.2
    #
    #    b) Django + Gunicorn in web-ns
    #       - Example: create a Django project and run Gunicorn. For demonstration:
    # run_process_in_namespace(web_ns, "django-admin startproject myproject /tmp/myproject")
    # run_process_in_namespace(web_ns, "gunicorn --chdir /tmp/myproject myproject.wsgi:application --bind 0.0.0.0:8000")
    #
    #    c) Nginx in web-ns
    #       - run_process_in_namespace(web_ns, "service nginx start")
    #
    #    d) FRR in frr-ns
    #       - run_process_in_namespace(frr_ns, "service frr start")
    #       - or run zebra, bgpd, etc. individually with nsenter
    #
    # For demonstration, let's just do a simple sleep in each namespace:
    run_process_in_namespace(web_ns,  "bash -c 'echo Running in web-ns; sleep 10 &'")
    run_process_in_namespace(db_ns,   "bash -c 'echo Running in db-ns; sleep 10 &'")
    run_process_in_namespace(frr_ns,  "bash -c 'echo Running in frr-ns; sleep 10 &'")

    print("All namespaces set up. Sleeping 15 seconds before cleanup...")
    time.sleep(15)

    # 5. CLEANUP (comment out if you want to keep the namespaces)
    for ns in [web_ns, db_ns, frr_ns]:
        delete_namespace(ns)

if __name__ == "__main__":
    # You must run as root (or with sudo).
    if os.geteuid() != 0:
        print("Please run this script with sudo or as root.")
        exit(1)
    main()
```

### How This Works

1. **Create Namespaces**  
   - `ip netns add <namespace>`: Creates an isolated network stack.

2. **Loopback Setup**  
   - We enable the loopback device in each namespace:  
     ```
     ip netns exec <namespace> ip link set lo up
     ```

3. **Assigning IP Addresses**  
   - We give each namespace a unique IP on its loopback or VXLAN interface.

4. **Creating the VXLAN**  
   - `ip link add vxlan0 type vxlan id 100 dev eth0 local <IP> remote <IP>`  
   - If you have multiple hosts or a more complex topology, you can specify a `remote` or a multicast group.  

5. **Running Processes**  
   - `ip netns exec <namespace> <command>`:  
     - Enters the namespace’s network stack and runs the command there.  
     - In a real setup, you might start a service (Nginx, Gunicorn, PostgreSQL, FRR daemons, etc.) in each namespace.  

6. **Cleanup**  
   - `ip netns delete <namespace>`: Removes the namespace and its associated virtual interfaces.  

---

## Expanding to Match Your Diagram

- **Multiple Pods**: Create more namespaces (POD 000, POD 001, etc.) to match your diagram.  
- **AI Engine, SIEM, IDS**: You can run additional containers or processes in separate namespaces.  
- **Database / Analytics**: For each data store or analytics engine, either install it in a dedicated namespace or spin up a Docker container with a custom network namespace.  
- **Routing**: In the `frr-ns`, install and configure `zebra`, `bgpd`, or other FRR daemons to dynamically route between the different subnets or VXLAN segments.  
- **VPN / Firewall**: You could add iptables/nftables rules in each namespace or a dedicated firewall namespace to replicate the firewall/IDS portion of your diagram.  

---

### Using Docker Instead of Raw Namespaces

If you prefer Docker (or LXD) to manage containers:

1. Create a custom Docker network using a VXLAN driver (or macvlan/bridge).  
2. Spin up containers for Django/Nginx, PostgreSQL, FRR, etc.  
3. Pass in the `--network` or `--net=none` flags and manually attach containers to custom networks using `pipework` or `CNI` plugins.  

---

### Using Systemd-nspawn or LXC

For a more “OS container” style approach, you can combine:

- `machinectl` / `systemd-nspawn` or LXC for containers (which also handle cgroups, PIDs, etc.).  
- Then manually create or attach each container’s network interface (veth, macvlan, VXLAN, etc.) to a namespace.  

---

## Conclusion

This script should give you a **starting point** to replicate the high-level design from your diagram:

- **Multiple network namespaces**  
- **VXLAN overlay**  
- **Isolated container-like processes** (web stack with Django, Nginx, Gunicorn, PostgreSQL, FRR, etc.)  

You will need to customize:

- IP addresses and subnets  
- Actual package installation  
- Configuration for FRR, PostgreSQL, Nginx, Django, etc.  

…but the core idea of using `ip netns`, `ip link`, `vxlan`, and `nsenter` remains the same. Good luck!
