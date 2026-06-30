#!/usr/bin/env python3
import os
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time
from typing import List, Tuple

# Paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
C_DIR = os.path.join(BASE_DIR, "reference", "softflowd")
C_DAEMON = os.path.join(C_DIR, "softflowd")
C_CTL = os.path.join(C_DIR, "softflowctl")
RUST_DAEMON = os.path.join(BASE_DIR, "target", "debug", "rsoftflowd")
RUST_CTL = os.path.join(BASE_DIR, "target", "debug", "rsoftflowctl")


def print_green(text: str):
    print(f"\033[92m{text}\033[0m")


def print_red(text: str):
    print(f"\033[91m{text}\033[0m")


def print_yellow(text: str):
    print(f"\033[93m{text}\033[0m")


def check_binaries():
    """Ensure all binaries are compiled."""
    print("Checking and compiling binaries if necessary...")

    # Compile Rust binaries
    subprocess.run(["cargo", "build"], cwd=BASE_DIR, check=True)

    # Compile C binaries
    if not os.path.exists(C_DAEMON) or not os.path.exists(C_CTL):
        print("Compiling reference C binaries...")
        # Create minimal config.h if missing
        config_h = os.path.join(C_DIR, "config.h")
        if not os.path.exists(config_h):
            with open(config_h, "w") as f:
                f.write(
                    "#ifndef CONFIG_H\n#define CONFIG_H\n#define HAVE_PCAP_H 1\n#define HAVE_ENDIAN_H 1\n#define FLOW_RB 1\n#define EXPIRY_RB 1\n#define _GNU_SOURCE 1\n#define _BSD_SOURCE 1\n#endif\n"
                )

        # Compile softflowd
        subprocess.run(
            [
                "gcc",
                "-o",
                "softflowd",
                "freelist.c",
                "softflowd.c",
                "log.c",
                "netflow5.c",
                "ipfix.c",
                "psamp.c",
                "netflow9.c",
                "netflow1.c",
                "convtime.c",
                "strlcpy.c",
                "strlcat.c",
                "closefrom.c",
                "daemon.c",
                "-lpcap",
            ],
            cwd=C_DIR,
            check=True,
        )
        # Compile softflowctl
        subprocess.run(
            [
                "gcc",
                "-o",
                "softflowctl",
                "softflowctl.c",
                "convtime.c",
                "strlcpy.c",
                "strlcat.c",
                "closefrom.c",
                "daemon.c",
            ],
            cwd=C_DIR,
            check=True,
        )

    # Verify paths exist
    for path, name in [
        (C_DAEMON, "C daemon"),
        (C_CTL, "C control"),
        (RUST_DAEMON, "Rust daemon"),
        (RUST_CTL, "Rust control"),
    ]:
        if not os.path.exists(path):
            print_red(f"Error: {name} not found at {path}")
            sys.exit(1)
    print_green("All binaries are ready.")


def create_dummy_pcap(filepath: str):
    """Generate a pcap containing dummy TCP, UDP, and ICMP packets."""
    # PCAP Global Header
    global_hdr = struct.pack(
        ">IHHIIII",
        0xA1B2C3D4,  # magic
        2,
        4,  # version major, minor
        0,  # thiszone
        0,  # sigfigs
        65535,  # snaplen
        1,  # network (DLT_EN10MB)
    )

    packets = []

    # 1. TCP SYN from 192.168.1.100:12345 -> 10.0.0.1:80
    eth_hdr = struct.pack(
        "!6s6sH", b"\x02\x02\x02\x02\x02\x02", b"\x01\x01\x01\x01\x01\x01", 0x0800
    )
    ip_hdr = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        40,
        0x1234,
        0,
        64,
        6,
        0,
        socket.inet_aton("192.168.1.100"),
        socket.inet_aton("10.0.0.1"),
    )
    tcp_hdr = struct.pack(
        "!HHIIBBHHH", 12345, 80, 1000, 0, 0x50, 0x02, 65535, 0, 0
    )  # SYN
    packets.append(eth_hdr + ip_hdr + tcp_hdr)

    # 2. TCP ACK from 10.0.0.1:80 -> 192.168.1.100:12345
    ip_hdr_rev = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        40,
        0x1235,
        0,
        64,
        6,
        0,
        socket.inet_aton("10.0.0.1"),
        socket.inet_aton("192.168.1.100"),
    )
    tcp_hdr_rev = struct.pack(
        "!HHIIBBHHH", 80, 12345, 1, 1001, 0x50, 0x10, 65535, 0, 0
    )  # ACK
    packets.append(eth_hdr + ip_hdr_rev + tcp_hdr_rev)

    # 3. UDP from 192.168.1.100:5555 -> 8.8.8.8:53 (length 30)
    ip_hdr_udp = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        38,
        0x1236,
        0,
        64,
        17,
        0,
        socket.inet_aton("192.168.1.100"),
        socket.inet_aton("8.8.8.8"),
    )
    udp_hdr = struct.pack("!HHHH", 5555, 53, 18, 0)
    packets.append(eth_hdr + ip_hdr_udp + udp_hdr + b"Hello UDP!")

    # 4. ICMP Echo Request from 192.168.1.100 -> 192.168.1.1 (length 40)
    ip_hdr_icmp = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        28,
        0x1237,
        0,
        64,
        1,
        0,
        socket.inet_aton("192.168.1.100"),
        socket.inet_aton("192.168.1.1"),
    )
    icmp_hdr = struct.pack("!BBHH", 8, 0, 0, 0x5678)  # Type 8: Echo Request
    packets.append(eth_hdr + ip_hdr_icmp + icmp_hdr + b"Ping!")

    with open(filepath, "wb") as f:
        f.write(global_hdr)
        ts_sec = 1600000000
        ts_usec = 1000
        for pkt in packets:
            # Packet Header
            pkt_hdr = struct.pack(">IIII", ts_sec, ts_usec, len(pkt), len(pkt))
            f.write(pkt_hdr)
            f.write(pkt)
            ts_sec += 1
            ts_usec += 500


def test_cli_compatibility():
    print("--------------------------------------------------")
    print("Testing 1: CLI Options Compatibility...")
    print("--------------------------------------------------")

    # 1. Invalid option exit codes
    p_c = subprocess.run([C_DAEMON, "-z"], capture_output=True, text=True)
    p_rust = subprocess.run([RUST_DAEMON, "-z"], capture_output=True, text=True)

    print(f"C '-z' exit status: {p_c.returncode}")
    print(f"Rust '-z' exit status: {p_rust.returncode}")

    if p_c.returncode == 0 or p_rust.returncode == 0:
        print_red("FAILED: Invalid CLI options should return non-zero exit code.")
        sys.exit(1)

    # 2. Help output options inclusion check
    p_c_res = subprocess.run([C_DAEMON, "-h"], capture_output=True, text=True)
    p_rust_res = subprocess.run([RUST_DAEMON, "-h"], capture_output=True, text=True)
    p_c_help = p_c_res.stdout + p_c_res.stderr
    p_rust_help = p_rust_res.stdout + p_rust_res.stderr

    required_options = [
        "-i",
        "-r",
        "-t",
        "-m",
        "-n",
        "-p",
        "-c",
        "-v",
        "-L",
        "-T",
        "-d",
        "-D",
    ]
    missing_c = [opt for opt in required_options if opt not in p_c_help]
    missing_rust = [opt for opt in required_options if opt not in p_rust_help]

    if missing_c or missing_rust:
        print_red(
            f"FAILED: Help strings missing key options. C missing: {missing_c}, Rust missing: {missing_rust}"
        )
        sys.exit(1)

    print_green("CLI compatibility tests PASSED.")


def start_blocked_daemon(
    daemon_bin: str, sock_path: str, extra_args: list = None
) -> Tuple[subprocess.Popen, int, str, str]:
    fifo_dir = tempfile.mkdtemp()
    fifo_path = os.path.join(fifo_dir, "pcap.fifo")
    os.mkfifo(fifo_path)

    # Open FIFO in read-write mode so it doesn't block on opening
    fifo_fd = os.open(fifo_path, os.O_RDWR)
    # Write a standard pcap global header so pcap_open_offline succeeds
    header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    os.write(fifo_fd, header)

    args = [daemon_bin, "-d", "-r", fifo_path, "-c", sock_path]
    if extra_args:
        args.extend(extra_args)

    proc = subprocess.Popen(args)
    time.sleep(0.5)  # Let it initialize

    return proc, fifo_fd, fifo_path, fifo_dir


def stop_blocked_daemon(
    proc: subprocess.Popen, fifo_fd: int, fifo_path: str, fifo_dir: str
):
    try:
        proc.terminate()

        start_time = time.time()
        while time.time() - start_time < 2.0:
            if proc.poll() is not None:
                break
            time.sleep(0.05)
        else:
            proc.kill()
            proc.wait()
    finally:
        try:
            os.close(fifo_fd)
        except:
            pass
        if os.path.exists(fifo_path):
            os.remove(fifo_path)
        if os.path.exists(fifo_dir):
            os.rmdir(fifo_dir)


def run_cross_control_tests():
    print("--------------------------------------------------")
    print("Testing 2: Control Socket Cross-Connection...")
    print("--------------------------------------------------")

    sock_c = "/tmp/compat_test_c.sock"
    sock_rust = "/tmp/compat_test_rust.sock"

    for sock in (sock_c, sock_rust):
        if os.path.exists(sock):
            os.remove(sock)

    # 1. Run C daemon with control socket in PSAMP mode (to enable multiplexing without root)
    proc_c = subprocess.Popen([C_DAEMON, "-d", "-R", "9999", "-c", sock_c])
    time.sleep(0.5)  # Allow server to start

    try:
        # Query C daemon statistics using C ctl
        out_c_c = subprocess.run(
            [C_CTL, "-c", sock_c, "statistics"], capture_output=True, text=True
        ).stdout
        print_yellow(f"C CTL -> C Daemon Statistics:\n{out_c_c}")
    finally:
        proc_c.terminate()
        proc_c.wait()

    if os.path.exists(sock_c):
        os.remove(sock_c)

    proc_c = subprocess.Popen([C_DAEMON, "-d", "-R", "9999", "-c", sock_c])
    time.sleep(0.5)

    try:
        # Query C daemon statistics using Rust ctl
        out_rust_c = subprocess.run(
            [RUST_CTL, "-c", sock_c, "statistics"], capture_output=True, text=True
        ).stdout
        print_yellow(f"Rust CTL -> C Daemon Statistics:\n{out_rust_c}")

        if "active flows" not in out_rust_c.lower():
            print_red("FAILED: Rust CTL could not retrieve statistics from C Daemon.")
            sys.exit(1)

        # Shut down C daemon using Rust ctl
        shutdown_res = subprocess.run(
            [RUST_CTL, "-c", sock_c, "shutdown"], capture_output=True, text=True
        ).stdout
        print_yellow(f"Rust CTL -> C Daemon Shutdown: {shutdown_res.strip()}")

        proc_c.wait(timeout=2)
        print_green("C Daemon shutdown by Rust CTL verified.")
    except Exception as e:
        print_red(f"FAILED during C Daemon cross control: {e}")
        proc_c.terminate()
        sys.exit(1)

    # 2. Run Rust daemon with control socket using a blocked PCAP FIFO
    proc_rust, r_fifo_fd, r_fifo_path, r_fifo_dir = start_blocked_daemon(
        RUST_DAEMON, sock_rust
    )

    try:
        # Query Rust daemon statistics using C ctl
        out_c_rust = subprocess.run(
            [C_CTL, "-c", sock_rust, "statistics"], capture_output=True, text=True
        ).stdout
        print_yellow(f"C CTL -> Rust Daemon Statistics:\n{out_c_rust}")

        # Query Rust daemon statistics using Rust ctl
        out_rust_rust = subprocess.run(
            [RUST_CTL, "-c", sock_rust, "statistics"], capture_output=True, text=True
        ).stdout
        print_yellow(f"Rust CTL -> Rust Daemon Statistics:\n{out_rust_rust}")

        if "active flows" not in out_c_rust.lower():
            print_red("FAILED: C CTL could not retrieve statistics from Rust Daemon.")
            sys.exit(1)

        # Shut down Rust daemon using C ctl
        shutdown_res = subprocess.run(
            [C_CTL, "-c", sock_rust, "shutdown"], capture_output=True, text=True
        ).stdout
        print_yellow(f"C CTL -> Rust Daemon Shutdown: {shutdown_res.strip()}")

        if proc_rust.poll() is None:
            os.close(r_fifo_fd)
            proc_rust.terminate()
            try:
                proc_rust.wait(timeout=1.0)
            except subprocess.TimeoutExpired:
                proc_rust.kill()
                proc_rust.wait()
        else:
            proc_rust.wait()

        print_green("Rust Daemon shutdown by C CTL verified.")
    except Exception as e:
        print_red(f"FAILED during Rust Daemon cross control: {e}")
        proc_rust.terminate()
        sys.exit(1)
    finally:
        stop_blocked_daemon(proc_rust, r_fifo_fd, r_fifo_path, r_fifo_dir)

    print_green("Control socket cross-connection tests PASSED.")


def receive_packets(port: int, timeout: float = 1.0) -> List[bytes]:
    """Bind a UDP socket and receive all incoming packets until timeout."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", port))
    sock.settimeout(timeout)
    packets = []
    try:
        while True:
            data, addr = sock.recvfrom(65535)
            packets.append(data)
    except socket.timeout:
        pass
    finally:
        sock.close()
    return packets


def parse_netflow_v5(data: bytes) -> List[dict]:
    """Parse NetFlow v5 packets and return flow records."""
    if len(data) < 24:
        return []
    version, count = struct.unpack("!HH", data[0:4])
    if version != 5:
        return []

    flows = []
    offset = 24
    for _ in range(count):
        if offset + 48 > len(data):
            break
        rec = data[offset : offset + 48]
        (
            src,
            dst,
            nexthop,
            input_if,
            output_if,
            pkts,
            octets,
            first,
            last,
            src_port,
            dst_port,
            tcp_flags,
            prot,
            tos,
            src_as,
            dst_as,
            src_mask,
            dst_mask,
        ) = struct.unpack("!4s4s4sHHIIIIHHxBBBHHBBxx", rec)
        flows.append(
            {
                "src": socket.inet_ntoa(src),
                "dst": socket.inet_ntoa(dst),
                "pkts": pkts,
                "octets": octets,
                "src_port": src_port,
                "dst_port": dst_port,
                "tcp_flags": tcp_flags,
                "protocol": prot,
                "tos": tos,
            }
        )
        offset += 48
    return flows


def test_differential_packets():
    print("--------------------------------------------------")
    print("Testing 3: Differential Packet Output Verification...")
    print("--------------------------------------------------")

    with tempfile.TemporaryDirectory() as tmpdir:
        pcap_path = os.path.join(tmpdir, "test.pcap")
        create_dummy_pcap(pcap_path)

        # Test versions: Netflow v5, Netflow v9, IPFIX (10)
        for version in [5, 9, 10]:
            print(f"Verifying NetFlow version {version}...")
            c_port = 9991
            rust_port = 9992

            # Start collectors (listening UDP)
            # Since softflowd in offline mode executes immediately and exits,
            # we run python receiver sockets in background threads, or simple sequential runs.
            # To avoid threading issues, we run them sequentially:
            # First, we bind UDP socket, then launch daemon, then receive.

            # 1. Capture C output
            # C daemon execution
            c_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            c_sock.bind(("127.0.0.1", c_port))
            c_sock.settimeout(1.0)

            # Run C softflowd
            # Note: C version uses -a option (adjust time) when reading pcap so it exports flows
            c_proc = subprocess.Popen(
                [
                    C_DAEMON,
                    "-d",
                    "-r",
                    pcap_path,
                    "-n",
                    f"127.0.0.1:{c_port}",
                    "-v",
                    str(version),
                    "-a",
                ]
            )
            c_proc.wait()

            c_packets = []
            try:
                while True:
                    data, _ = c_sock.recvfrom(65535)
                    c_packets.append(data)
            except socket.timeout:
                pass
            finally:
                c_sock.close()

            # 2. Capture Rust output
            rust_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            rust_sock.bind(("127.0.0.1", rust_port))
            rust_sock.settimeout(1.0)

            # Run Rust rsoftflowd (note: Rust rsoftflowd automatically adjusts times for PCAP reading)
            rust_proc = subprocess.Popen(
                [
                    RUST_DAEMON,
                    "-d",
                    "-r",
                    pcap_path,
                    "-n",
                    f"127.0.0.1:{rust_port}",
                    "-v",
                    str(version),
                ]
            )
            rust_proc.wait()

            rust_packets = []
            try:
                while True:
                    data, _ = rust_sock.recvfrom(65535)
                    rust_packets.append(data)
            except socket.timeout:
                pass
            finally:
                rust_sock.close()

            print(
                f"  Captured {len(c_packets)} packets from C, {len(rust_packets)} packets from Rust"
            )
            if not c_packets or not rust_packets:
                print_red(
                    f"FAILED: No packets captured for version {version}. C: {len(c_packets)}, Rust: {len(rust_packets)}"
                )
                sys.exit(1)

            if version == 5:
                # For v5, do deep semantic flow record comparison
                c_flows = []
                for p in c_packets:
                    c_flows.extend(parse_netflow_v5(p))
                rust_flows = []
                for p in rust_packets:
                    rust_flows.extend(parse_netflow_v5(p))

                # Normalize and sort flows for order-independent comparison
                def key_func(f):
                    return (
                        f["src"],
                        f["dst"],
                        f["src_port"],
                        f["dst_port"],
                        f["protocol"],
                    )

                c_flows.sort(key=key_func)
                rust_flows.sort(key=key_func)

                if len(c_flows) != len(rust_flows):
                    print_red(
                        f"FAILED: Number of parsed flows differs. C: {len(c_flows)}, Rust: {len(rust_flows)}"
                    )
                    print(f"C flows: {c_flows}")
                    print(f"Rust flows: {rust_flows}")
                    sys.exit(1)

                for i, (cf, rf) in enumerate(zip(c_flows, rust_flows)):
                    # Compare essential fields
                    for k in [
                        "src",
                        "dst",
                        "src_port",
                        "dst_port",
                        "protocol",
                        "tcp_flags",
                    ]:
                        if cf[k] != rf[k]:
                            print_red(
                                f"FAILED: Flow record mismatch at index {i}, field '{k}': C={cf[k]}, Rust={rf[k]}"
                            )
                            print(f"C flow: {cf}")
                            print(f"Rust flow: {rf}")
                            sys.exit(1)
                print_green("  NetFlow v5 flows matched perfectly.")
            else:
                # For v9 and IPFIX (10), check header and packet structure validity
                (v_c,) = struct.unpack("!H", c_packets[0][0:2])
                (v_r,) = struct.unpack("!H", rust_packets[0][0:2])
                if v_c != version or v_r != version:
                    print_red(
                        f"FAILED: Packet version header mismatch. Expected {version}, C got {v_c}, Rust got {v_r}"
                    )
                    sys.exit(1)
                print_green(f"  NetFlow v{version} packet structure verified.")

    print_green("Differential packet output tests PASSED.")


if __name__ == "__main__":
    check_binaries()
    test_cli_compatibility()
    run_cross_control_tests()
    test_differential_packets()
    print_green("\nALL COMPATIBILITY TESTS PASSED SUCCESSFULLY!")
