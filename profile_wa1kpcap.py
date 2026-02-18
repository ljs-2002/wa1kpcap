"""Quick profiling script to find the real bottleneck."""
import cProfile
import pstats
import io
from wa1kpcap import Wa1kPcap

pcap = "D:/Project/Dataset/USTCTFC2016/ustc-tfc2016/Benign/Gmail.pcap"

analyzer = Wa1kPcap(filter_ack=True, bpf_filter="tcp or udp", verbose_mode=False)

pr = cProfile.Profile()
pr.enable()
flows = analyzer.analyze_file(pcap)
pr.disable()

s = io.StringIO()
ps = pstats.Stats(pr, stream=s).sort_stats("cumulative")
ps.print_stats(40)
print(s.getvalue())

print("=" * 60)
s2 = io.StringIO()
ps2 = pstats.Stats(pr, stream=s2).sort_stats("tottime")
ps2.print_stats(40)
print(s2.getvalue())
