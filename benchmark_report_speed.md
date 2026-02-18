# wa1kpcap Benchmark: dpkt vs native C++ engine

- Date: 2026-02-16 16:29:06
- Python: 3.10.16
- Mode: speed
- BPF filter: `tcp or udp`
- Config: `filter_ack=False, verbose_mode=False`

## 2. Speed Benchmark

### USTCTFC2016

- Path: `D:\Project\Dataset\USTCTFC2016\ustc-tfc2016`
- Files: 24
- Total size: 3.716 GB

| Metric | dpkt | native | flowcontainer |
|--------|------|--------|---------------|
| Total time | 411.01s | 331.93s | 372.60s |
| Speed | 9.3 MB/s | 11.5 MB/s | 10.2 MB/s |
| Speedup (vs dpkt) | 1.00x | 1.24x | 1.10x |

#### Per-file results

| File | Size (MB) | dpkt (s) | native (s) | fc (s) | native speedup | fc speedup |
|------|-----------|----------|------------|--------|----------------|------------|
| BitTorrent.pcap | 7.3 | 1.32 | 1.44 | 1.17 | 0.92x | 1.13x |
| Facetime.pcap | 2.4 | 0.49 | 0.33 | 0.71 | 1.47x | 0.68x |
| FTP.pcap | 60.2 | 25.90 | 24.96 | 28.39 | 1.04x | 0.91x |
| Gmail.pcap | 9.1 | 4.62 | 1.74 | 2.05 | 2.65x | 2.26x |
| MySQL.pcap | 22.4 | 15.93 | 17.71 | 15.61 | 0.90x | 1.02x |
| Outlook.pcap | 11.2 | 1.49 | 1.53 | 1.50 | 0.97x | 0.99x |
| Skype.pcap | 4.2 | 3.36 | 2.88 | 1.72 | 1.17x | 1.96x |
| SMB-1.pcap | 1034.0 | 55.56 | 46.94 | 50.43 | 1.18x | 1.10x |
| SMB-2.pcap | 206.8 | 9.23 | 9.25 | 9.78 | 1.00x | 0.94x |
| Weibo-1.pcap | 1033.8 | 68.17 | 55.27 | 64.52 | 1.23x | 1.06x |
| Weibo-2.pcap | 206.8 | 11.57 | 11.45 | 14.94 | 1.01x | 0.77x |
| Weibo-3.pcap | 206.8 | 14.22 | 10.43 | 12.40 | 1.36x | 1.15x |
| Weibo-4.pcap | 206.8 | 13.53 | 12.18 | 12.40 | 1.11x | 1.09x |
| WorldOfWarcraft.pcap | 14.9 | 11.11 | 7.71 | 9.19 | 1.44x | 1.21x |
| Cridex.pcap | 94.8 | 29.37 | 22.57 | 29.59 | 1.30x | 0.99x |
| Geodo.pcap | 28.9 | 14.82 | 12.02 | 10.75 | 1.23x | 1.38x |
| Htbot.pcap | 83.6 | 16.32 | 13.19 | 12.10 | 1.24x | 1.35x |
| Miuref.pcap | 16.4 | 4.91 | 4.25 | 5.01 | 1.16x | 0.98x |
| Neris.pcap | 90.1 | 33.68 | 23.45 | 29.16 | 1.44x | 1.15x |
| Nsis-ay.pcap | 281.2 | 22.72 | 12.39 | 17.79 | 1.83x | 1.28x |
| Shifu.pcap | 57.9 | 16.41 | 9.50 | 16.29 | 1.73x | 1.01x |
| Tinba.pcap | 2.6 | 1.87 | 1.55 | 1.54 | 1.21x | 1.21x |
| Virut.pcap | 109.3 | 28.12 | 24.31 | 21.13 | 1.16x | 1.33x |
| Zeus.pcap | 13.4 | 6.29 | 4.88 | 4.45 | 1.29x | 1.41x |

## 3. Summary

| Dataset | Files | Size (GB) | dpkt (s) | native (s) | fc (s) | native speedup | fc speedup |
|---------|-------|-----------|----------|------------|--------|----------------|------------|
| USTCTFC2016 | 24 | 3.716 | 411.01 | 331.93 | 372.60 | 1.24x | 1.10x |
