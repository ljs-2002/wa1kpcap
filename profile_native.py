"""Profile native engine pipeline breakdown on specific pcap files."""
import cProfile
import pstats
import io
from wa1kpcap import Wa1kPcap

FILES = [
    "D:/Project/Dataset/USTCTFC2016/ustc-tfc2016/Benign/Skype.pcap",
    "D:/Project/Dataset/USTCTFC2016/ustc-tfc2016/Benign/FTP.pcap",
]

BPF = "tcp or udp"

for pcap in FILES:
    print(f"\n{'='*70}")
    print(f"Profiling: {pcap.split('/')[-1]}")
    print(f"{'='*70}")

    analyzer = Wa1kPcap(
        engine="native", filter_ack=False, verbose_mode=False, bpf_filter=BPF
    )

    pr = cProfile.Profile()
    pr.enable()
    flows = analyzer.analyze_file(pcap)
    # Force IAT computation
    for f in flows:
        _ = f.iats
    pr.disable()

    s = io.StringIO()
    ps = pstats.Stats(pr, stream=s).sort_stats("cumulative")
    ps.print_stats(40)
    print(s.getvalue())

    # Also print tottime ranking
    s2 = io.StringIO()
    ps2 = pstats.Stats(pr, stream=s2).sort_stats("tottime")
    ps2.print_stats(40)
    print("\n--- Sorted by tottime ---")
    print(s2.getvalue())
