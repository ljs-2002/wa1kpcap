# TLS 分析报告

PCAP 文件: `D:\MyProgram\wa1kpcap1\test\multi.pcap`

分析引擎: wa1kpcap native + tshark 对比

TLS 流总数 (native): 47

## 各流详情 (wa1kpcap native 引擎)

### 流 1: `192.168.226.54:7700 <-> 120.53.53.53:443`

握手消息数: 0, 应用数据包数: 15

### 流 2: `192.168.226.54:7707 <-> 120.53.53.53:443`

握手消息数: 0, 应用数据包数: 16

### 流 3: `192.168.226.54:8018 <-> 111.31.204.105:443`

握手消息数: 0, 应用数据包数: 1

### 流 4: `192.168.226.54:8907 <-> 111.13.142.55:443`

握手消息数: 7, 应用数据包数: 8

| # | 方向 | 类型 | 名称 | SNI | Cipher Suites | Cipher Suite | ALPN | Supported Groups | Signature Algorithms |
|---|------|------|------|-----|---------------|--------------|------|------------------|---------------------|
| 1 | 192.168.226.54:8907 -> 111.13.142.55:443 | 1 | ClientHello | tracking.miui.com | 0x1302, 0x1301, 0xc02c, 0xc02b, 0xc030, 0xc02f, 0xc024, 0xc023, 0xc028, 0xc02... | - | h2, http/1.1 | 0x001d, 0x0017, 0x0018 | 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0201, 0x0403, 0x0503, 0x0203, 0x0202, 0x0601, 0x0603 |
| 2 | 111.13.142.55:443 -> 192.168.226.54:8907 | 2 | ServerHello | - | - | 0xc02f | h2 | - | - |
| 3 | 111.13.142.55:443 -> 192.168.226.54:8907 | 11 | Certificate | - | - | - | - | - | - |
| 4 | 111.13.142.55:443 -> 192.168.226.54:8907 | 12 | ServerKeyExchange | - | - | - | - | - | - |
| 5 | 111.13.142.55:443 -> 192.168.226.54:8907 | 14 | ServerHelloDone | - | - | - | - | - | - |
| 6 | 192.168.226.54:8907 -> 111.13.142.55:443 | 16 | ClientKeyExchange | - | - | - | - | - | - |
| 7 | 111.13.142.55:443 -> 192.168.226.54:8907 | 4 | NewSessionTicket | - | - | - | - | - | - |

**证书链 (2 张证书):**

**证书 1:**

- Subject: `CN=*.miui.com`
- Issuer: `C=US, O=DigiCert Inc, OU=www.digicert.com, CN=Encryption Everywhere DV TLS CA - G1`
- Serial: `0x1fe1eb19b229903608487f29a520727`
- Not Before: `2024-11-08T00:00:00+00:00`
- Not After: `2025-11-07T23:59:59+00:00`
- SHA-256: `5a6a03ba54f5fd218bb6ee124f1618d3a3f8bd824be58292835ee80e690619e1`

**证书 2:**

- Subject: `C=US, O=DigiCert Inc, OU=www.digicert.com, CN=Encryption Everywhere DV TLS CA - G1`
- Issuer: `C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert Global Root CA`
- Serial: `0x279ac458bc1b245abf98053cd2c9bb1`
- Not Before: `2017-11-27T12:46:10+00:00`
- Not After: `2027-11-27T12:46:10+00:00`
- SHA-256: `15eb0a75c673abfbdcd2fafc02823c91fe6cbc36e00788442c8754d72bec3717`

### 流 5: `192.168.226.54:8922 <-> 111.13.142.55:443`

握手消息数: 7, 应用数据包数: 8

| # | 方向 | 类型 | 名称 | SNI | Cipher Suites | Cipher Suite | ALPN | Supported Groups | Signature Algorithms |
|---|------|------|------|-----|---------------|--------------|------|------------------|---------------------|
| 1 | 192.168.226.54:8922 -> 111.13.142.55:443 | 1 | ClientHello | tracking.miui.com | 0x1302, 0x1301, 0xc02c, 0xc02b, 0xc030, 0xc02f, 0xc024, 0xc023, 0xc028, 0xc02... | - | h2, http/1.1 | 0x001d, 0x0017, 0x0018 | 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0201, 0x0403, 0x0503, 0x0203, 0x0202, 0x0601, 0x0603 |
| 2 | 111.13.142.55:443 -> 192.168.226.54:8922 | 2 | ServerHello | - | - | 0xc02f | h2 | - | - |
| 3 | 111.13.142.55:443 -> 192.168.226.54:8922 | 11 | Certificate | - | - | - | - | - | - |
| 4 | 111.13.142.55:443 -> 192.168.226.54:8922 | 12 | ServerKeyExchange | - | - | - | - | - | - |
| 5 | 111.13.142.55:443 -> 192.168.226.54:8922 | 14 | ServerHelloDone | - | - | - | - | - | - |
| 6 | 192.168.226.54:8922 -> 111.13.142.55:443 | 16 | ClientKeyExchange | - | - | - | - | - | - |
| 7 | 111.13.142.55:443 -> 192.168.226.54:8922 | 4 | NewSessionTicket | - | - | - | - | - | - |

**证书链 (2 张证书):**

**证书 1:**

- Subject: `CN=*.miui.com`
- Issuer: `C=US, O=DigiCert Inc, OU=www.digicert.com, CN=Encryption Everywhere DV TLS CA - G1`
- Serial: `0x1fe1eb19b229903608487f29a520727`
- Not Before: `2024-11-08T00:00:00+00:00`
- Not After: `2025-11-07T23:59:59+00:00`
- SHA-256: `5a6a03ba54f5fd218bb6ee124f1618d3a3f8bd824be58292835ee80e690619e1`

**证书 2:**

- Subject: `C=US, O=DigiCert Inc, OU=www.digicert.com, CN=Encryption Everywhere DV TLS CA - G1`
- Issuer: `C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert Global Root CA`
- Serial: `0x279ac458bc1b245abf98053cd2c9bb1`
- Not Before: `2017-11-27T12:46:10+00:00`
- Not After: `2027-11-27T12:46:10+00:00`
- SHA-256: `15eb0a75c673abfbdcd2fafc02823c91fe6cbc36e00788442c8754d72bec3717`

### 流 6: `192.168.226.54:8926 <-> 20.50.73.13:443`

握手消息数: 4, 应用数据包数: 10

| # | 方向 | 类型 | 名称 | SNI | Cipher Suites | Cipher Suite | ALPN | Supported Groups | Signature Algorithms |
|---|------|------|------|-----|---------------|--------------|------|------------------|---------------------|
| 1 | 192.168.226.54:8926 -> 20.50.73.13:443 | 1 | ClientHello | mobile.events.data.microsoft.com | 0x8a8a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca... | - | h2, http/1.1 | 0xaaaa, 0x11ec, 0x001d, 0x0017, 0x0018 | 0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601 |
| 2 | 20.50.73.13:443 -> 192.168.226.54:8926 | 2 | ServerHello | - | - | 0x1302 | - | - | - |
| 3 | 192.168.226.54:8926 -> 20.50.73.13:443 | 1 | ClientHello | mobile.events.data.microsoft.com | 0x8a8a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca... | - | h2, http/1.1 | 0xaaaa, 0x11ec, 0x001d, 0x0017, 0x0018 | 0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601 |
| 4 | 20.50.73.13:443 -> 192.168.226.54:8926 | 2 | ServerHello | - | - | 0x1302 | - | - | - |

### 流 7: `192.168.226.54:8927 <-> 223.5.5.5:443`

握手消息数: 2, 应用数据包数: 5

| # | 方向 | 类型 | 名称 | SNI | Cipher Suites | Cipher Suite | ALPN | Supported Groups | Signature Algorithms |
|---|------|------|------|-----|---------------|--------------|------|------------------|---------------------|
| 1 | 192.168.226.54:8927 -> 223.5.5.5:443 | 1 | ClientHello | - | 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc009, 0xc013, 0xc00a, 0xc01... | - | http/1.1, h2 | 0x001d, 0x0017, 0x0018, 0x0019 | 0x0804, 0x0403, 0x0807, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0503, 0x0603, 0x0201, 0x0203 |
| 2 | 223.5.5.5:443 -> 192.168.226.54:8927 | 2 | ServerHello | - | - | 0x1301 | - | - | - |

### 流 8: `192.168.226.54:8928 <-> 223.5.5.5:443`

握手消息数: 2, 应用数据包数: 21

| # | 方向 | 类型 | 名称 | SNI | Cipher Suites | Cipher Suite | ALPN | Supported Groups | Signature Algorithms |
|---|------|------|------|-----|---------------|--------------|------|------------------|---------------------|
| 1 | 192.168.226.54:8928 -> 223.5.5.5:443 | 1 | ClientHello | - | 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc009, 0xc013, 0xc00a, 0xc01... | - | http/1.1, h2 | 0x001d, 0x0017, 0x0018, 0x0019 | 0x0804, 0x0403, 0x0807, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0503, 0x0603, 0x0201, 0x0203 |
| 2 | 223.5.5.5:443 -> 192.168.226.54:8928 | 2 | ServerHello | - | - | 0x1301 | - | - | - |

### 流 9: `192.168.226.54:8929 <-> 223.6.6.6:853`

握手消息数: 2, 应用数据包数: 1

| # | 方向 | 类型 | 名称 | SNI | Cipher Suites | Cipher Suite | ALPN | Supported Groups | Signature Algorithms |
|---|------|------|------|-----|---------------|--------------|------|------------------|---------------------|
| 1 | 192.168.226.54:8929 -> 223.6.6.6:853 | 1 | ClientHello | - | 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc009, 0xc013, 0xc00a, 0xc01... | - | - | 0x001d, 0x0017, 0x0018, 0x0019 | 0x0804, 0x0403, 0x0807, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0503, 0x0603, 0x0201, 0x0203 |
| 2 | 223.6.6.6:853 -> 192.168.226.54:8929 | 2 | ServerHello | - | - | 0x1301 | - | - | - |

### 流 10: `192.168.226.54:8930 <-> 223.5.5.5:853`

握手消息数: 2, 应用数据包数: 1

| # | 方向 | 类型 | 名称 | SNI | Cipher Suites | Cipher Suite | ALPN | Supported Groups | Signature Algorithms |
|---|------|------|------|-----|---------------|--------------|------|------------------|---------------------|
| 1 | 192.168.226.54:8930 -> 223.5.5.5:853 | 1 | ClientHello | - | 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc009, 0xc013, 0xc00a, 0xc01... | - | - | 0x001d, 0x0017, 0x0018, 0x0019 | 0x0804, 0x0403, 0x0807, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0503, 0x0603, 0x0201, 0x0203 |
| 2 | 223.5.5.5:853 -> 192.168.226.54:8930 | 2 | ServerHello | - | - | 0x1301 | - | - | - |

### 流 11: `192.168.226.54:8931 <-> 223.6.6.6:443`

握手消息数: 2, 应用数据包数: 12

| # | 方向 | 类型 | 名称 | SNI | Cipher Suites | Cipher Suite | ALPN | Supported Groups | Signature Algorithms |
|---|------|------|------|-----|---------------|--------------|------|------------------|---------------------|
| 1 | 192.168.226.54:8931 -> 223.6.6.6:443 | 1 | ClientHello | - | 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc009, 0xc013, 0xc00a, 0xc01... | - | http/1.1, h2 | 0x001d, 0x0017, 0x0018, 0x0019 | 0x0804, 0x0403, 0x0807, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0503, 0x0603, 0x0201, 0x0203 |
| 2 | 223.6.6.6:443 -> 192.168.226.54:8931 | 2 | ServerHello | - | - | 0x1301 | - | - | - |

### 流 12: `192.168.226.54:8932 <-> 120.53.53.53:853`

握手消息数: 5, 应用数据包数: 0

| # | 方向 | 类型 | 名称 | SNI | Cipher Suites | Cipher Suite | ALPN | Supported Groups | Signature Algorithms |
|---|------|------|------|-----|---------------|--------------|------|------------------|---------------------|
| 1 | 192.168.226.54:8932 -> 120.53.53.53:853 | 1 | ClientHello | dot.pub | 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc009, 0xc013, 0xc00a, 0xc01... | - | - | 0x001d, 0x0017, 0x0018, 0x0019 | 0x0804, 0x0403, 0x0807, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0503, 0x0603, 0x0201, 0x0203 |
| 2 | 120.53.53.53:853 -> 192.168.226.54:8932 | 2 | ServerHello | - | - | 0xc02b | - | - | - |
| 3 | 120.53.53.53:853 -> 192.168.226.54:8932 | 11 | Certificate | - | - | - | - | - | - |
| 4 | 120.53.53.53:853 -> 192.168.226.54:8932 | 12 | ServerKeyExchange | - | - | - | - | - | - |
| 5 | 120.53.53.53:853 -> 192.168.226.54:8932 | 14 | ServerHelloDone | - | - | - | - | - | - |

**证书链 (3 张证书):**

**证书 1:**

- Subject: `C=CN, ST=Guangdong Sheng, O=Tencent Technology(shenzhen)Company Limited, CN=120.53.53.53`
- Issuer: `C=CN, O=TrustAsia Technologies, Inc., CN=TrustAsia ECC OV TLS CA G3`
- Serial: `0xc6b5597f7adb6642c93b31666567ac1d`
- Not Before: `2024-11-19T00:00:00+00:00`
- Not After: `2025-12-19T23:59:59+00:00`
- SHA-256: `edef5e6bf8669289acd70e59fec9bc7d9962492af8699858403fa222482a2bbc`

**证书 2:**

- Subject: `C=CN, O=TrustAsia Technologies, Inc., CN=TrustAsia ECC OV TLS CA G3`
- Issuer: `C=US, ST=New Jersey, L=Jersey City, O=The USERTRUST Network, CN=USERTrust ECC Certification Authority`
- Serial: `0x4df7309184c7b632b600b5d4a045e959`
- Not Before: `2022-04-20T00:00:00+00:00`
- Not After: `2032-04-19T23:59:59+00:00`
- SHA-256: `397808dab0765b2d224831fcd34bfe56a4093f14c48a700727bb31a7ad420cb4`

**证书 3:**

- Subject: `C=US, ST=New Jersey, L=Jersey City, O=The USERTRUST Network, CN=USERTrust ECC Certification Authority`
- Issuer: `C=GB, ST=Greater Manchester, L=Salford, O=Comodo CA Limited, CN=AAA Certificate Services`
- Serial: `0x56671d04ea4f994c6f10814759d27594`
- Not Before: `2019-03-12T00:00:00+00:00`
- Not After: `2028-12-31T23:59:59+00:00`
- SHA-256: `a6cf64dbb4c8d5fd19ce48896068db03b533a8d1336c6256a87d00cbb3def3ea`

### 流 13: `192.168.226.54:8933 <-> 223.5.5.5:853`

握手消息数: 2, 应用数据包数: 1

| # | 方向 | 类型 | 名称 | SNI | Cipher Suites | Cipher Suite | ALPN | Supported Groups | Signature Algorithms |
|---|------|------|------|-----|---------------|--------------|------|------------------|---------------------|
| 1 | 192.168.226.54:8933 -> 223.5.5.5:853 | 1 | ClientHello | dns.alidns.com | 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc009, 0xc013, 0xc00a, 0xc01... | - | - | 0x001d, 0x0017, 0x0018, 0x0019 | 0x0804, 0x0403, 0x0807, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0503, 0x0603, 0x0201, 0x0203 |
| 2 | 223.5.5.5:853 -> 192.168.226.54:8933 | 2 | ServerHello | - | - | 0x1301 | - | - | - |

### 流 14: `192.168.226.54:8934 <-> 223.6.6.6:853`

握手消息数: 2, 应用数据包数: 7

| # | 方向 | 类型 | 名称 | SNI | Cipher Suites | Cipher Suite | ALPN | Supported Groups | Signature Algorithms |
|---|------|------|------|-----|---------------|--------------|------|------------------|---------------------|
| 1 | 192.168.226.54:8934 -> 223.6.6.6:853 | 1 | ClientHello | - | 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc009, 0xc013, 0xc00a, 0xc01... | - | - | 0x001d, 0x0017, 0x0018, 0x0019 | 0x0804, 0x0403, 0x0807, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0503, 0x0603, 0x0201, 0x0203 |
| 2 | 223.6.6.6:853 -> 192.168.226.54:8934 | 2 | ServerHello | - | - | 0x1301 | - | - | - |

### 流 15: `192.168.226.54:8935 <-> 223.5.5.5:853`

握手消息数: 2, 应用数据包数: 7

| # | 方向 | 类型 | 名称 | SNI | Cipher Suites | Cipher Suite | ALPN | Supported Groups | Signature Algorithms |
|---|------|------|------|-----|---------------|--------------|------|------------------|---------------------|
| 1 | 192.168.226.54:8935 -> 223.5.5.5:853 | 1 | ClientHello | - | 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc009, 0xc013, 0xc00a, 0xc01... | - | - | 0x001d, 0x0017, 0x0018, 0x0019 | 0x0804, 0x0403, 0x0807, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0503, 0x0603, 0x0201, 0x0203 |
| 2 | 223.5.5.5:853 -> 192.168.226.54:8935 | 2 | ServerHello | - | - | 0x1301 | - | - | - |

### 流 16: `192.168.226.54:8936 <-> 223.6.6.6:853`

握手消息数: 2, 应用数据包数: 7

| # | 方向 | 类型 | 名称 | SNI | Cipher Suites | Cipher Suite | ALPN | Supported Groups | Signature Algorithms |
|---|------|------|------|-----|---------------|--------------|------|------------------|---------------------|
| 1 | 192.168.226.54:8936 -> 223.6.6.6:853 | 1 | ClientHello | dns.alidns.com | 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc009, 0xc013, 0xc00a, 0xc01... | - | - | 0x001d, 0x0017, 0x0018, 0x0019 | 0x0804, 0x0403, 0x0807, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0503, 0x0603, 0x0201, 0x0203 |
| 2 | 223.6.6.6:853 -> 192.168.226.54:8936 | 2 | ServerHello | - | - | 0x1301 | - | - | - |

### 流 17: `192.168.226.54:8937 <-> 223.6.6.6:443`

握手消息数: 2, 应用数据包数: 4

| # | 方向 | 类型 | 名称 | SNI | Cipher Suites | Cipher Suite | ALPN | Supported Groups | Signature Algorithms |
|---|------|------|------|-----|---------------|--------------|------|------------------|---------------------|
| 1 | 192.168.226.54:8937 -> 223.6.6.6:443 | 1 | ClientHello | - | 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc009, 0xc013, 0xc00a, 0xc01... | - | http/1.1, h2 | 0x001d, 0x0017, 0x0018, 0x0019 | 0x0804, 0x0403, 0x0807, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0503, 0x0603, 0x0201, 0x0203 |
| 2 | 223.6.6.6:443 -> 192.168.226.54:8937 | 2 | ServerHello | - | - | 0x1301 | - | - | - |

### 流 18: `192.168.226.54:8938 <-> 120.53.53.53:853`

握手消息数: 6, 应用数据包数: 2

| # | 方向 | 类型 | 名称 | SNI | Cipher Suites | Cipher Suite | ALPN | Supported Groups | Signature Algorithms |
|---|------|------|------|-----|---------------|--------------|------|------------------|---------------------|
| 1 | 192.168.226.54:8938 -> 120.53.53.53:853 | 1 | ClientHello | dot.pub | 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc009, 0xc013, 0xc00a, 0xc01... | - | - | 0x001d, 0x0017, 0x0018, 0x0019 | 0x0804, 0x0403, 0x0807, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0503, 0x0603, 0x0201, 0x0203 |
| 2 | 120.53.53.53:853 -> 192.168.226.54:8938 | 2 | ServerHello | - | - | 0xc02b | - | - | - |
| 3 | 120.53.53.53:853 -> 192.168.226.54:8938 | 11 | Certificate | - | - | - | - | - | - |
| 4 | 120.53.53.53:853 -> 192.168.226.54:8938 | 12 | ServerKeyExchange | - | - | - | - | - | - |
| 5 | 120.53.53.53:853 -> 192.168.226.54:8938 | 14 | ServerHelloDone | - | - | - | - | - | - |
| 6 | 192.168.226.54:8938 -> 120.53.53.53:853 | 16 | ClientKeyExchange | - | - | - | - | - | - |

**证书链 (3 张证书):**

**证书 1:**

- Subject: `C=CN, ST=Guangdong Sheng, O=Tencent Technology(shenzhen)Company Limited, CN=120.53.53.53`
- Issuer: `C=CN, O=TrustAsia Technologies, Inc., CN=TrustAsia ECC OV TLS CA G3`
- Serial: `0xc6b5597f7adb6642c93b31666567ac1d`
- Not Before: `2024-11-19T00:00:00+00:00`
- Not After: `2025-12-19T23:59:59+00:00`
- SHA-256: `edef5e6bf8669289acd70e59fec9bc7d9962492af8699858403fa222482a2bbc`

**证书 2:**

- Subject: `C=CN, O=TrustAsia Technologies, Inc., CN=TrustAsia ECC OV TLS CA G3`
- Issuer: `C=US, ST=New Jersey, L=Jersey City, O=The USERTRUST Network, CN=USERTrust ECC Certification Authority`
- Serial: `0x4df7309184c7b632b600b5d4a045e959`
- Not Before: `2022-04-20T00:00:00+00:00`
- Not After: `2032-04-19T23:59:59+00:00`
- SHA-256: `397808dab0765b2d224831fcd34bfe56a4093f14c48a700727bb31a7ad420cb4`

**证书 3:**

- Subject: `C=US, ST=New Jersey, L=Jersey City, O=The USERTRUST Network, CN=USERTrust ECC Certification Authority`
- Issuer: `C=GB, ST=Greater Manchester, L=Salford, O=Comodo CA Limited, CN=AAA Certificate Services`
- Serial: `0x56671d04ea4f994c6f10814759d27594`
- Not Before: `2019-03-12T00:00:00+00:00`
- Not After: `2028-12-31T23:59:59+00:00`
- SHA-256: `a6cf64dbb4c8d5fd19ce48896068db03b533a8d1336c6256a87d00cbb3def3ea`

### 流 19: `192.168.226.54:8963 <-> 20.42.73.25:443`

握手消息数: 6, 应用数据包数: 7

| # | 方向 | 类型 | 名称 | SNI | Cipher Suites | Cipher Suite | ALPN | Supported Groups | Signature Algorithms |
|---|------|------|------|-----|---------------|--------------|------|------------------|---------------------|
| 1 | 192.168.226.54:8963 -> 20.42.73.25:443 | 1 | ClientHello | v20.events.data.microsoft.com | 0xc02c, 0xc02b, 0xc030, 0xc02f, 0xc024, 0xc023, 0xc028, 0xc027, 0xc00a, 0xc00... | - | h2, http/1.1 | 0x001d, 0x0017, 0x0018 | 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0201, 0x0403, 0x0503, 0x0203, 0x0202, 0x0601, 0x0603 |
| 2 | 20.42.73.25:443 -> 192.168.226.54:8963 | 2 | ServerHello | - | - | 0xc030 | h2 | - | - |
| 3 | 20.42.73.25:443 -> 192.168.226.54:8963 | 11 | Certificate | - | - | - | h2 | - | - |
| 4 | 20.42.73.25:443 -> 192.168.226.54:8963 | 12 | ServerKeyExchange | - | - | - | h2 | - | - |
| 5 | 20.42.73.25:443 -> 192.168.226.54:8963 | 14 | ServerHelloDone | - | - | - | h2 | - | - |
| 6 | 192.168.226.54:8963 -> 20.42.73.25:443 | 16 | ClientKeyExchange | - | - | - | - | - | - |

**证书链 (2 张证书):**

**证书 1:**

- Subject: `C=US, ST=WA, L=Redmond, O=Microsoft, OU=WSE, CN=*.events.data.microsoft.com`
- Issuer: `C=US, ST=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Secure Server CA 2011`
- Serial: `0x330000039ba67c63062748977400000000039b`
- Not Before: `2025-05-17T02:31:02+00:00`
- Not After: `2026-05-17T02:31:02+00:00`
- SHA-256: `eaa5d81a7b8f409340731a903a86ebb04a3d2e9bc99b515c1ca338c8c1bdc5f7`

**证书 2:**

- Subject: `C=US, ST=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Secure Server CA 2011`
- Issuer: `C=US, ST=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Root Certificate Authority 2011`
- Serial: `0x613fb718000000000004`
- Not Before: `2011-10-18T22:55:19+00:00`
- Not After: `2026-10-18T23:05:19+00:00`
- SHA-256: `83688f2aef71386e0936c4b3013b07e8e0c796d8427716dd48b2a63d79509129`

### 流 20: `192.168.226.54:8964 <-> 223.5.5.5:443`

握手消息数: 2, 应用数据包数: 5

| # | 方向 | 类型 | 名称 | SNI | Cipher Suites | Cipher Suite | ALPN | Supported Groups | Signature Algorithms |
|---|------|------|------|-----|---------------|--------------|------|------------------|---------------------|
| 1 | 192.168.226.54:8964 -> 223.5.5.5:443 | 1 | ClientHello | - | 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc009, 0xc013, 0xc00a, 0xc01... | - | http/1.1, h2 | 0x001d, 0x0017, 0x0018, 0x0019 | 0x0804, 0x0403, 0x0807, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0503, 0x0603, 0x0201, 0x0203 |
| 2 | 223.5.5.5:443 -> 192.168.226.54:8964 | 2 | ServerHello | - | - | 0x1301 | - | - | - |

### 流 21: `192.168.226.54:8965 <-> 223.5.5.5:443`

握手消息数: 2, 应用数据包数: 21

| # | 方向 | 类型 | 名称 | SNI | Cipher Suites | Cipher Suite | ALPN | Supported Groups | Signature Algorithms |
|---|------|------|------|-----|---------------|--------------|------|------------------|---------------------|
| 1 | 192.168.226.54:8965 -> 223.5.5.5:443 | 1 | ClientHello | - | 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc009, 0xc013, 0xc00a, 0xc01... | - | http/1.1, h2 | 0x001d, 0x0017, 0x0018, 0x0019 | 0x0804, 0x0403, 0x0807, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0503, 0x0603, 0x0201, 0x0203 |
| 2 | 223.5.5.5:443 -> 192.168.226.54:8965 | 2 | ServerHello | - | - | 0x1301 | - | - | - |

### 流 22: `192.168.226.54:8966 <-> 223.6.6.6:443`

握手消息数: 2, 应用数据包数: 13

| # | 方向 | 类型 | 名称 | SNI | Cipher Suites | Cipher Suite | ALPN | Supported Groups | Signature Algorithms |
|---|------|------|------|-----|---------------|--------------|------|------------------|---------------------|
| 1 | 192.168.226.54:8966 -> 223.6.6.6:443 | 1 | ClientHello | - | 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc009, 0xc013, 0xc00a, 0xc01... | - | http/1.1, h2 | 0x001d, 0x0017, 0x0018, 0x0019 | 0x0804, 0x0403, 0x0807, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0503, 0x0603, 0x0201, 0x0203 |
| 2 | 223.6.6.6:443 -> 192.168.226.54:8966 | 2 | ServerHello | - | - | 0x1301 | - | - | - |

### 流 23: `192.168.226.54:8967 <-> 120.53.53.53:853`

握手消息数: 5, 应用数据包数: 0

| # | 方向 | 类型 | 名称 | SNI | Cipher Suites | Cipher Suite | ALPN | Supported Groups | Signature Algorithms |
|---|------|------|------|-----|---------------|--------------|------|------------------|---------------------|
| 1 | 192.168.226.54:8967 -> 120.53.53.53:853 | 1 | ClientHello | dot.pub | 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc009, 0xc013, 0xc00a, 0xc01... | - | - | 0x001d, 0x0017, 0x0018, 0x0019 | 0x0804, 0x0403, 0x0807, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0503, 0x0603, 0x0201, 0x0203 |
| 2 | 120.53.53.53:853 -> 192.168.226.54:8967 | 2 | ServerHello | - | - | 0xc02b | - | - | - |
| 3 | 120.53.53.53:853 -> 192.168.226.54:8967 | 11 | Certificate | - | - | - | - | - | - |
| 4 | 120.53.53.53:853 -> 192.168.226.54:8967 | 12 | ServerKeyExchange | - | - | - | - | - | - |
| 5 | 120.53.53.53:853 -> 192.168.226.54:8967 | 14 | ServerHelloDone | - | - | - | - | - | - |

**证书链 (3 张证书):**

**证书 1:**

- Subject: `C=CN, ST=Guangdong Sheng, O=Tencent Technology(shenzhen)Company Limited, CN=120.53.53.53`
- Issuer: `C=CN, O=TrustAsia Technologies, Inc., CN=TrustAsia ECC OV TLS CA G3`
- Serial: `0xc6b5597f7adb6642c93b31666567ac1d`
- Not Before: `2024-11-19T00:00:00+00:00`
- Not After: `2025-12-19T23:59:59+00:00`
- SHA-256: `edef5e6bf8669289acd70e59fec9bc7d9962492af8699858403fa222482a2bbc`

**证书 2:**

- Subject: `C=CN, O=TrustAsia Technologies, Inc., CN=TrustAsia ECC OV TLS CA G3`
- Issuer: `C=US, ST=New Jersey, L=Jersey City, O=The USERTRUST Network, CN=USERTrust ECC Certification Authority`
- Serial: `0x4df7309184c7b632b600b5d4a045e959`
- Not Before: `2022-04-20T00:00:00+00:00`
- Not After: `2032-04-19T23:59:59+00:00`
- SHA-256: `397808dab0765b2d224831fcd34bfe56a4093f14c48a700727bb31a7ad420cb4`

**证书 3:**

- Subject: `C=US, ST=New Jersey, L=Jersey City, O=The USERTRUST Network, CN=USERTrust ECC Certification Authority`
- Issuer: `C=GB, ST=Greater Manchester, L=Salford, O=Comodo CA Limited, CN=AAA Certificate Services`
- Serial: `0x56671d04ea4f994c6f10814759d27594`
- Not Before: `2019-03-12T00:00:00+00:00`
- Not After: `2028-12-31T23:59:59+00:00`
- SHA-256: `a6cf64dbb4c8d5fd19ce48896068db03b533a8d1336c6256a87d00cbb3def3ea`

### 流 24: `192.168.226.54:8968 <-> 223.6.6.6:853`

握手消息数: 2, 应用数据包数: 1

| # | 方向 | 类型 | 名称 | SNI | Cipher Suites | Cipher Suite | ALPN | Supported Groups | Signature Algorithms |
|---|------|------|------|-----|---------------|--------------|------|------------------|---------------------|
| 1 | 192.168.226.54:8968 -> 223.6.6.6:853 | 1 | ClientHello | - | 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc009, 0xc013, 0xc00a, 0xc01... | - | - | 0x001d, 0x0017, 0x0018, 0x0019 | 0x0804, 0x0403, 0x0807, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0503, 0x0603, 0x0201, 0x0203 |
| 2 | 223.6.6.6:853 -> 192.168.226.54:8968 | 2 | ServerHello | - | - | 0x1301 | - | - | - |

### 流 25: `192.168.226.54:8969 <-> 223.5.5.5:853`

握手消息数: 2, 应用数据包数: 1

| # | 方向 | 类型 | 名称 | SNI | Cipher Suites | Cipher Suite | ALPN | Supported Groups | Signature Algorithms |
|---|------|------|------|-----|---------------|--------------|------|------------------|---------------------|
| 1 | 192.168.226.54:8969 -> 223.5.5.5:853 | 1 | ClientHello | - | 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc009, 0xc013, 0xc00a, 0xc01... | - | - | 0x001d, 0x0017, 0x0018, 0x0019 | 0x0804, 0x0403, 0x0807, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0503, 0x0603, 0x0201, 0x0203 |
| 2 | 223.5.5.5:853 -> 192.168.226.54:8969 | 2 | ServerHello | - | - | 0x1301 | - | - | - |

### 流 26: `192.168.226.54:8970 <-> 223.6.6.6:853`

握手消息数: 2, 应用数据包数: 1

| # | 方向 | 类型 | 名称 | SNI | Cipher Suites | Cipher Suite | ALPN | Supported Groups | Signature Algorithms |
|---|------|------|------|-----|---------------|--------------|------|------------------|---------------------|
| 1 | 192.168.226.54:8970 -> 223.6.6.6:853 | 1 | ClientHello | dns.alidns.com | 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc009, 0xc013, 0xc00a, 0xc01... | - | - | 0x001d, 0x0017, 0x0018, 0x0019 | 0x0804, 0x0403, 0x0807, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0503, 0x0603, 0x0201, 0x0203 |
| 2 | 223.6.6.6:853 -> 192.168.226.54:8970 | 2 | ServerHello | - | - | 0x1301 | - | - | - |

### 流 27: `192.168.226.54:8971 <-> 223.6.6.6:853`

握手消息数: 2, 应用数据包数: 7

| # | 方向 | 类型 | 名称 | SNI | Cipher Suites | Cipher Suite | ALPN | Supported Groups | Signature Algorithms |
|---|------|------|------|-----|---------------|--------------|------|------------------|---------------------|
| 1 | 192.168.226.54:8971 -> 223.6.6.6:853 | 1 | ClientHello | - | 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc009, 0xc013, 0xc00a, 0xc01... | - | - | 0x001d, 0x0017, 0x0018, 0x0019 | 0x0804, 0x0403, 0x0807, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0503, 0x0603, 0x0201, 0x0203 |
| 2 | 223.6.6.6:853 -> 192.168.226.54:8971 | 2 | ServerHello | - | - | 0x1301 | - | - | - |

### 流 28: `192.168.226.54:8972 <-> 223.5.5.5:853`

握手消息数: 2, 应用数据包数: 7

| # | 方向 | 类型 | 名称 | SNI | Cipher Suites | Cipher Suite | ALPN | Supported Groups | Signature Algorithms |
|---|------|------|------|-----|---------------|--------------|------|------------------|---------------------|
| 1 | 192.168.226.54:8972 -> 223.5.5.5:853 | 1 | ClientHello | dns.alidns.com | 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc009, 0xc013, 0xc00a, 0xc01... | - | - | 0x001d, 0x0017, 0x0018, 0x0019 | 0x0804, 0x0403, 0x0807, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0503, 0x0603, 0x0201, 0x0203 |
| 2 | 223.5.5.5:853 -> 192.168.226.54:8972 | 2 | ServerHello | - | - | 0x1301 | - | - | - |

### 流 29: `192.168.226.54:8973 <-> 223.6.6.6:443`

握手消息数: 2, 应用数据包数: 5

| # | 方向 | 类型 | 名称 | SNI | Cipher Suites | Cipher Suite | ALPN | Supported Groups | Signature Algorithms |
|---|------|------|------|-----|---------------|--------------|------|------------------|---------------------|
| 1 | 192.168.226.54:8973 -> 223.6.6.6:443 | 1 | ClientHello | - | 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc009, 0xc013, 0xc00a, 0xc01... | - | http/1.1, h2 | 0x001d, 0x0017, 0x0018, 0x0019 | 0x0804, 0x0403, 0x0807, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0503, 0x0603, 0x0201, 0x0203 |
| 2 | 223.6.6.6:443 -> 192.168.226.54:8973 | 2 | ServerHello | - | - | 0x1301 | - | - | - |

### 流 30: `192.168.226.54:8974 <-> 223.5.5.5:853`

握手消息数: 2, 应用数据包数: 7

| # | 方向 | 类型 | 名称 | SNI | Cipher Suites | Cipher Suite | ALPN | Supported Groups | Signature Algorithms |
|---|------|------|------|-----|---------------|--------------|------|------------------|---------------------|
| 1 | 192.168.226.54:8974 -> 223.5.5.5:853 | 1 | ClientHello | - | 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc009, 0xc013, 0xc00a, 0xc01... | - | - | 0x001d, 0x0017, 0x0018, 0x0019 | 0x0804, 0x0403, 0x0807, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0503, 0x0603, 0x0201, 0x0203 |
| 2 | 223.5.5.5:853 -> 192.168.226.54:8974 | 2 | ServerHello | - | - | 0x1301 | - | - | - |

### 流 31: `192.168.226.54:8975 <-> 1.12.12.21:853`

握手消息数: 6, 应用数据包数: 1

| # | 方向 | 类型 | 名称 | SNI | Cipher Suites | Cipher Suite | ALPN | Supported Groups | Signature Algorithms |
|---|------|------|------|-----|---------------|--------------|------|------------------|---------------------|
| 1 | 192.168.226.54:8975 -> 1.12.12.21:853 | 1 | ClientHello | dot.pub | 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc009, 0xc013, 0xc00a, 0xc01... | - | - | 0x001d, 0x0017, 0x0018, 0x0019 | 0x0804, 0x0403, 0x0807, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0503, 0x0603, 0x0201, 0x0203 |
| 2 | 1.12.12.21:853 -> 192.168.226.54:8975 | 2 | ServerHello | - | - | 0xc02b | - | - | - |
| 3 | 1.12.12.21:853 -> 192.168.226.54:8975 | 11 | Certificate | - | - | - | - | - | - |
| 4 | 1.12.12.21:853 -> 192.168.226.54:8975 | 12 | ServerKeyExchange | - | - | - | - | - | - |
| 5 | 1.12.12.21:853 -> 192.168.226.54:8975 | 14 | ServerHelloDone | - | - | - | - | - | - |
| 6 | 192.168.226.54:8975 -> 1.12.12.21:853 | 16 | ClientKeyExchange | - | - | - | - | - | - |

**证书链 (3 张证书):**

**证书 1:**

- Subject: `C=CN, ST=Guangdong Sheng, O=Tencent Technology(shenzhen)Company Limited, CN=120.53.53.53`
- Issuer: `C=CN, O=TrustAsia Technologies, Inc., CN=TrustAsia ECC OV TLS CA G3`
- Serial: `0xc6b5597f7adb6642c93b31666567ac1d`
- Not Before: `2024-11-19T00:00:00+00:00`
- Not After: `2025-12-19T23:59:59+00:00`
- SHA-256: `edef5e6bf8669289acd70e59fec9bc7d9962492af8699858403fa222482a2bbc`

**证书 2:**

- Subject: `C=CN, O=TrustAsia Technologies, Inc., CN=TrustAsia ECC OV TLS CA G3`
- Issuer: `C=US, ST=New Jersey, L=Jersey City, O=The USERTRUST Network, CN=USERTrust ECC Certification Authority`
- Serial: `0x4df7309184c7b632b600b5d4a045e959`
- Not Before: `2022-04-20T00:00:00+00:00`
- Not After: `2032-04-19T23:59:59+00:00`
- SHA-256: `397808dab0765b2d224831fcd34bfe56a4093f14c48a700727bb31a7ad420cb4`

**证书 3:**

- Subject: `C=US, ST=New Jersey, L=Jersey City, O=The USERTRUST Network, CN=USERTrust ECC Certification Authority`
- Issuer: `C=GB, ST=Greater Manchester, L=Salford, O=Comodo CA Limited, CN=AAA Certificate Services`
- Serial: `0x56671d04ea4f994c6f10814759d27594`
- Not Before: `2019-03-12T00:00:00+00:00`
- Not After: `2028-12-31T23:59:59+00:00`
- SHA-256: `a6cf64dbb4c8d5fd19ce48896068db03b533a8d1336c6256a87d00cbb3def3ea`

### 流 32: `192.168.226.54:9008 <-> 111.13.142.55:443`

握手消息数: 7, 应用数据包数: 8

| # | 方向 | 类型 | 名称 | SNI | Cipher Suites | Cipher Suite | ALPN | Supported Groups | Signature Algorithms |
|---|------|------|------|-----|---------------|--------------|------|------------------|---------------------|
| 1 | 192.168.226.54:9008 -> 111.13.142.55:443 | 1 | ClientHello | tracking.miui.com | 0x1302, 0x1301, 0xc02c, 0xc02b, 0xc030, 0xc02f, 0xc024, 0xc023, 0xc028, 0xc02... | - | h2, http/1.1 | 0x001d, 0x0017, 0x0018 | 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0201, 0x0403, 0x0503, 0x0203, 0x0202, 0x0601, 0x0603 |
| 2 | 111.13.142.55:443 -> 192.168.226.54:9008 | 2 | ServerHello | - | - | 0xc02f | h2 | - | - |
| 3 | 111.13.142.55:443 -> 192.168.226.54:9008 | 11 | Certificate | - | - | - | - | - | - |
| 4 | 111.13.142.55:443 -> 192.168.226.54:9008 | 12 | ServerKeyExchange | - | - | - | - | - | - |
| 5 | 111.13.142.55:443 -> 192.168.226.54:9008 | 14 | ServerHelloDone | - | - | - | - | - | - |
| 6 | 192.168.226.54:9008 -> 111.13.142.55:443 | 16 | ClientKeyExchange | - | - | - | - | - | - |
| 7 | 111.13.142.55:443 -> 192.168.226.54:9008 | 4 | NewSessionTicket | - | - | - | - | - | - |

**证书链 (2 张证书):**

**证书 1:**

- Subject: `CN=*.miui.com`
- Issuer: `C=US, O=DigiCert Inc, OU=www.digicert.com, CN=Encryption Everywhere DV TLS CA - G1`
- Serial: `0x1fe1eb19b229903608487f29a520727`
- Not Before: `2024-11-08T00:00:00+00:00`
- Not After: `2025-11-07T23:59:59+00:00`
- SHA-256: `5a6a03ba54f5fd218bb6ee124f1618d3a3f8bd824be58292835ee80e690619e1`

**证书 2:**

- Subject: `C=US, O=DigiCert Inc, OU=www.digicert.com, CN=Encryption Everywhere DV TLS CA - G1`
- Issuer: `C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert Global Root CA`
- Serial: `0x279ac458bc1b245abf98053cd2c9bb1`
- Not Before: `2017-11-27T12:46:10+00:00`
- Not After: `2027-11-27T12:46:10+00:00`
- SHA-256: `15eb0a75c673abfbdcd2fafc02823c91fe6cbc36e00788442c8754d72bec3717`

### 流 33: `192.168.226.54:9052 <-> 111.13.142.55:443`

握手消息数: 7, 应用数据包数: 8

| # | 方向 | 类型 | 名称 | SNI | Cipher Suites | Cipher Suite | ALPN | Supported Groups | Signature Algorithms |
|---|------|------|------|-----|---------------|--------------|------|------------------|---------------------|
| 1 | 192.168.226.54:9052 -> 111.13.142.55:443 | 1 | ClientHello | tracking.miui.com | 0x1302, 0x1301, 0xc02c, 0xc02b, 0xc030, 0xc02f, 0xc024, 0xc023, 0xc028, 0xc02... | - | h2, http/1.1 | 0x001d, 0x0017, 0x0018 | 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0201, 0x0403, 0x0503, 0x0203, 0x0202, 0x0601, 0x0603 |
| 2 | 111.13.142.55:443 -> 192.168.226.54:9052 | 2 | ServerHello | - | - | 0xc02f | h2 | - | - |
| 3 | 111.13.142.55:443 -> 192.168.226.54:9052 | 11 | Certificate | - | - | - | - | - | - |
| 4 | 111.13.142.55:443 -> 192.168.226.54:9052 | 12 | ServerKeyExchange | - | - | - | - | - | - |
| 5 | 111.13.142.55:443 -> 192.168.226.54:9052 | 14 | ServerHelloDone | - | - | - | - | - | - |
| 6 | 192.168.226.54:9052 -> 111.13.142.55:443 | 16 | ClientKeyExchange | - | - | - | - | - | - |
| 7 | 111.13.142.55:443 -> 192.168.226.54:9052 | 4 | NewSessionTicket | - | - | - | - | - | - |

**证书链 (2 张证书):**

**证书 1:**

- Subject: `CN=*.miui.com`
- Issuer: `C=US, O=DigiCert Inc, OU=www.digicert.com, CN=Encryption Everywhere DV TLS CA - G1`
- Serial: `0x1fe1eb19b229903608487f29a520727`
- Not Before: `2024-11-08T00:00:00+00:00`
- Not After: `2025-11-07T23:59:59+00:00`
- SHA-256: `5a6a03ba54f5fd218bb6ee124f1618d3a3f8bd824be58292835ee80e690619e1`

**证书 2:**

- Subject: `C=US, O=DigiCert Inc, OU=www.digicert.com, CN=Encryption Everywhere DV TLS CA - G1`
- Issuer: `C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert Global Root CA`
- Serial: `0x279ac458bc1b245abf98053cd2c9bb1`
- Not Before: `2017-11-27T12:46:10+00:00`
- Not After: `2027-11-27T12:46:10+00:00`
- SHA-256: `15eb0a75c673abfbdcd2fafc02823c91fe6cbc36e00788442c8754d72bec3717`

### 流 34: `192.168.226.54:9060 <-> 223.5.5.5:443`

握手消息数: 2, 应用数据包数: 5

| # | 方向 | 类型 | 名称 | SNI | Cipher Suites | Cipher Suite | ALPN | Supported Groups | Signature Algorithms |
|---|------|------|------|-----|---------------|--------------|------|------------------|---------------------|
| 1 | 192.168.226.54:9060 -> 223.5.5.5:443 | 1 | ClientHello | - | 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc009, 0xc013, 0xc00a, 0xc01... | - | http/1.1, h2 | 0x001d, 0x0017, 0x0018, 0x0019 | 0x0804, 0x0403, 0x0807, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0503, 0x0603, 0x0201, 0x0203 |
| 2 | 223.5.5.5:443 -> 192.168.226.54:9060 | 2 | ServerHello | - | - | 0x1301 | - | - | - |

### 流 35: `192.168.226.54:9061 <-> 223.5.5.5:443`

握手消息数: 2, 应用数据包数: 9

| # | 方向 | 类型 | 名称 | SNI | Cipher Suites | Cipher Suite | ALPN | Supported Groups | Signature Algorithms |
|---|------|------|------|-----|---------------|--------------|------|------------------|---------------------|
| 1 | 192.168.226.54:9061 -> 223.5.5.5:443 | 1 | ClientHello | - | 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc009, 0xc013, 0xc00a, 0xc01... | - | http/1.1, h2 | 0x001d, 0x0017, 0x0018, 0x0019 | 0x0804, 0x0403, 0x0807, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0503, 0x0603, 0x0201, 0x0203 |
| 2 | 223.5.5.5:443 -> 192.168.226.54:9061 | 2 | ServerHello | - | - | 0x1301 | - | - | - |

### 流 36: `192.168.226.54:9062 <-> 223.5.5.5:443`

握手消息数: 2, 应用数据包数: 9

| # | 方向 | 类型 | 名称 | SNI | Cipher Suites | Cipher Suite | ALPN | Supported Groups | Signature Algorithms |
|---|------|------|------|-----|---------------|--------------|------|------------------|---------------------|
| 1 | 192.168.226.54:9062 -> 223.5.5.5:443 | 1 | ClientHello | - | 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc009, 0xc013, 0xc00a, 0xc01... | - | http/1.1, h2 | 0x001d, 0x0017, 0x0018, 0x0019 | 0x0804, 0x0403, 0x0807, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0503, 0x0603, 0x0201, 0x0203 |
| 2 | 223.5.5.5:443 -> 192.168.226.54:9062 | 2 | ServerHello | - | - | 0x1301 | - | - | - |

### 流 37: `192.168.226.54:9063 <-> 120.53.53.53:443`

握手消息数: 6, 应用数据包数: 8

| # | 方向 | 类型 | 名称 | SNI | Cipher Suites | Cipher Suite | ALPN | Supported Groups | Signature Algorithms |
|---|------|------|------|-----|---------------|--------------|------|------------------|---------------------|
| 1 | 192.168.226.54:9063 -> 120.53.53.53:443 | 1 | ClientHello | - | 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc009, 0xc013, 0xc00a, 0xc01... | - | http/1.1, h2 | 0x001d, 0x0017, 0x0018, 0x0019 | 0x0804, 0x0403, 0x0807, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0503, 0x0603, 0x0201, 0x0203 |
| 2 | 120.53.53.53:443 -> 192.168.226.54:9063 | 2 | ServerHello | - | - | 0xc02b | h2 | - | - |
| 3 | 120.53.53.53:443 -> 192.168.226.54:9063 | 11 | Certificate | - | - | - | - | - | - |
| 4 | 120.53.53.53:443 -> 192.168.226.54:9063 | 12 | ServerKeyExchange | - | - | - | - | - | - |
| 5 | 120.53.53.53:443 -> 192.168.226.54:9063 | 14 | ServerHelloDone | - | - | - | - | - | - |
| 6 | 192.168.226.54:9063 -> 120.53.53.53:443 | 16 | ClientKeyExchange | - | - | - | - | - | - |

**证书链 (3 张证书):**

**证书 1:**

- Subject: `C=CN, ST=Guangdong Sheng, O=Tencent Technology(shenzhen)Company Limited, CN=120.53.53.53`
- Issuer: `C=CN, O=TrustAsia Technologies, Inc., CN=TrustAsia ECC OV TLS CA G3`
- Serial: `0xc6b5597f7adb6642c93b31666567ac1d`
- Not Before: `2024-11-19T00:00:00+00:00`
- Not After: `2025-12-19T23:59:59+00:00`
- SHA-256: `edef5e6bf8669289acd70e59fec9bc7d9962492af8699858403fa222482a2bbc`

**证书 2:**

- Subject: `C=CN, O=TrustAsia Technologies, Inc., CN=TrustAsia ECC OV TLS CA G3`
- Issuer: `C=US, ST=New Jersey, L=Jersey City, O=The USERTRUST Network, CN=USERTrust ECC Certification Authority`
- Serial: `0x4df7309184c7b632b600b5d4a045e959`
- Not Before: `2022-04-20T00:00:00+00:00`
- Not After: `2032-04-19T23:59:59+00:00`
- SHA-256: `397808dab0765b2d224831fcd34bfe56a4093f14c48a700727bb31a7ad420cb4`

**证书 3:**

- Subject: `C=US, ST=New Jersey, L=Jersey City, O=The USERTRUST Network, CN=USERTrust ECC Certification Authority`
- Issuer: `C=GB, ST=Greater Manchester, L=Salford, O=Comodo CA Limited, CN=AAA Certificate Services`
- Serial: `0x56671d04ea4f994c6f10814759d27594`
- Not Before: `2019-03-12T00:00:00+00:00`
- Not After: `2028-12-31T23:59:59+00:00`
- SHA-256: `a6cf64dbb4c8d5fd19ce48896068db03b533a8d1336c6256a87d00cbb3def3ea`

### 流 38: `192.168.226.54:9064 <-> 120.53.53.53:443`

握手消息数: 6, 应用数据包数: 1

| # | 方向 | 类型 | 名称 | SNI | Cipher Suites | Cipher Suite | ALPN | Supported Groups | Signature Algorithms |
|---|------|------|------|-----|---------------|--------------|------|------------------|---------------------|
| 1 | 192.168.226.54:9064 -> 120.53.53.53:443 | 1 | ClientHello | - | 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc009, 0xc013, 0xc00a, 0xc01... | - | http/1.1, h2 | 0x001d, 0x0017, 0x0018, 0x0019 | 0x0804, 0x0403, 0x0807, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0503, 0x0603, 0x0201, 0x0203 |
| 2 | 120.53.53.53:443 -> 192.168.226.54:9064 | 2 | ServerHello | - | - | 0xc02b | h2 | - | - |
| 3 | 120.53.53.53:443 -> 192.168.226.54:9064 | 11 | Certificate | - | - | - | - | - | - |
| 4 | 120.53.53.53:443 -> 192.168.226.54:9064 | 12 | ServerKeyExchange | - | - | - | - | - | - |
| 5 | 120.53.53.53:443 -> 192.168.226.54:9064 | 14 | ServerHelloDone | - | - | - | - | - | - |
| 6 | 192.168.226.54:9064 -> 120.53.53.53:443 | 16 | ClientKeyExchange | - | - | - | - | - | - |

**证书链 (3 张证书):**

**证书 1:**

- Subject: `C=CN, ST=Guangdong Sheng, O=Tencent Technology(shenzhen)Company Limited, CN=120.53.53.53`
- Issuer: `C=CN, O=TrustAsia Technologies, Inc., CN=TrustAsia ECC OV TLS CA G3`
- Serial: `0xc6b5597f7adb6642c93b31666567ac1d`
- Not Before: `2024-11-19T00:00:00+00:00`
- Not After: `2025-12-19T23:59:59+00:00`
- SHA-256: `edef5e6bf8669289acd70e59fec9bc7d9962492af8699858403fa222482a2bbc`

**证书 2:**

- Subject: `C=CN, O=TrustAsia Technologies, Inc., CN=TrustAsia ECC OV TLS CA G3`
- Issuer: `C=US, ST=New Jersey, L=Jersey City, O=The USERTRUST Network, CN=USERTrust ECC Certification Authority`
- Serial: `0x4df7309184c7b632b600b5d4a045e959`
- Not Before: `2022-04-20T00:00:00+00:00`
- Not After: `2032-04-19T23:59:59+00:00`
- SHA-256: `397808dab0765b2d224831fcd34bfe56a4093f14c48a700727bb31a7ad420cb4`

**证书 3:**

- Subject: `C=US, ST=New Jersey, L=Jersey City, O=The USERTRUST Network, CN=USERTrust ECC Certification Authority`
- Issuer: `C=GB, ST=Greater Manchester, L=Salford, O=Comodo CA Limited, CN=AAA Certificate Services`
- Serial: `0x56671d04ea4f994c6f10814759d27594`
- Not Before: `2019-03-12T00:00:00+00:00`
- Not After: `2028-12-31T23:59:59+00:00`
- SHA-256: `a6cf64dbb4c8d5fd19ce48896068db03b533a8d1336c6256a87d00cbb3def3ea`

### 流 39: `192.168.226.54:9065 <-> 223.5.5.5:443`

握手消息数: 2, 应用数据包数: 9

| # | 方向 | 类型 | 名称 | SNI | Cipher Suites | Cipher Suite | ALPN | Supported Groups | Signature Algorithms |
|---|------|------|------|-----|---------------|--------------|------|------------------|---------------------|
| 1 | 192.168.226.54:9065 -> 223.5.5.5:443 | 1 | ClientHello | - | 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc009, 0xc013, 0xc00a, 0xc01... | - | http/1.1, h2 | 0x001d, 0x0017, 0x0018, 0x0019 | 0x0804, 0x0403, 0x0807, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0503, 0x0603, 0x0201, 0x0203 |
| 2 | 223.5.5.5:443 -> 192.168.226.54:9065 | 2 | ServerHello | - | - | 0x1301 | - | - | - |

### 流 40: `192.168.226.54:9068 <-> 120.53.53.53:443`

握手消息数: 6, 应用数据包数: 1

| # | 方向 | 类型 | 名称 | SNI | Cipher Suites | Cipher Suite | ALPN | Supported Groups | Signature Algorithms |
|---|------|------|------|-----|---------------|--------------|------|------------------|---------------------|
| 1 | 192.168.226.54:9068 -> 120.53.53.53:443 | 1 | ClientHello | - | 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc009, 0xc013, 0xc00a, 0xc01... | - | http/1.1, h2 | 0x001d, 0x0017, 0x0018, 0x0019 | 0x0804, 0x0403, 0x0807, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0503, 0x0603, 0x0201, 0x0203 |
| 2 | 120.53.53.53:443 -> 192.168.226.54:9068 | 2 | ServerHello | - | - | 0xc02b | h2 | - | - |
| 3 | 120.53.53.53:443 -> 192.168.226.54:9068 | 11 | Certificate | - | - | - | - | - | - |
| 4 | 120.53.53.53:443 -> 192.168.226.54:9068 | 12 | ServerKeyExchange | - | - | - | - | - | - |
| 5 | 120.53.53.53:443 -> 192.168.226.54:9068 | 14 | ServerHelloDone | - | - | - | - | - | - |
| 6 | 192.168.226.54:9068 -> 120.53.53.53:443 | 16 | ClientKeyExchange | - | - | - | - | - | - |

**证书链 (3 张证书):**

**证书 1:**

- Subject: `C=CN, ST=Guangdong Sheng, O=Tencent Technology(shenzhen)Company Limited, CN=120.53.53.53`
- Issuer: `C=CN, O=TrustAsia Technologies, Inc., CN=TrustAsia ECC OV TLS CA G3`
- Serial: `0xc6b5597f7adb6642c93b31666567ac1d`
- Not Before: `2024-11-19T00:00:00+00:00`
- Not After: `2025-12-19T23:59:59+00:00`
- SHA-256: `edef5e6bf8669289acd70e59fec9bc7d9962492af8699858403fa222482a2bbc`

**证书 2:**

- Subject: `C=CN, O=TrustAsia Technologies, Inc., CN=TrustAsia ECC OV TLS CA G3`
- Issuer: `C=US, ST=New Jersey, L=Jersey City, O=The USERTRUST Network, CN=USERTrust ECC Certification Authority`
- Serial: `0x4df7309184c7b632b600b5d4a045e959`
- Not Before: `2022-04-20T00:00:00+00:00`
- Not After: `2032-04-19T23:59:59+00:00`
- SHA-256: `397808dab0765b2d224831fcd34bfe56a4093f14c48a700727bb31a7ad420cb4`

**证书 3:**

- Subject: `C=US, ST=New Jersey, L=Jersey City, O=The USERTRUST Network, CN=USERTrust ECC Certification Authority`
- Issuer: `C=GB, ST=Greater Manchester, L=Salford, O=Comodo CA Limited, CN=AAA Certificate Services`
- Serial: `0x56671d04ea4f994c6f10814759d27594`
- Not Before: `2019-03-12T00:00:00+00:00`
- Not After: `2028-12-31T23:59:59+00:00`
- SHA-256: `a6cf64dbb4c8d5fd19ce48896068db03b533a8d1336c6256a87d00cbb3def3ea`

### 流 41: `192.168.226.54:9069 <-> 223.5.5.5:443`

握手消息数: 2, 应用数据包数: 8

| # | 方向 | 类型 | 名称 | SNI | Cipher Suites | Cipher Suite | ALPN | Supported Groups | Signature Algorithms |
|---|------|------|------|-----|---------------|--------------|------|------------------|---------------------|
| 1 | 192.168.226.54:9069 -> 223.5.5.5:443 | 1 | ClientHello | - | 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc009, 0xc013, 0xc00a, 0xc01... | - | http/1.1, h2 | 0x001d, 0x0017, 0x0018, 0x0019 | 0x0804, 0x0403, 0x0807, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0503, 0x0603, 0x0201, 0x0203 |
| 2 | 223.5.5.5:443 -> 192.168.226.54:9069 | 2 | ServerHello | - | - | 0x1301 | - | - | - |

### 流 42: `192.168.226.54:9070 <-> 223.5.5.5:443`

握手消息数: 2, 应用数据包数: 4

| # | 方向 | 类型 | 名称 | SNI | Cipher Suites | Cipher Suite | ALPN | Supported Groups | Signature Algorithms |
|---|------|------|------|-----|---------------|--------------|------|------------------|---------------------|
| 1 | 192.168.226.54:9070 -> 223.5.5.5:443 | 1 | ClientHello | - | 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc009, 0xc013, 0xc00a, 0xc01... | - | http/1.1, h2 | 0x001d, 0x0017, 0x0018, 0x0019 | 0x0804, 0x0403, 0x0807, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0503, 0x0603, 0x0201, 0x0203 |
| 2 | 223.5.5.5:443 -> 192.168.226.54:9070 | 2 | ServerHello | - | - | 0x1301 | - | - | - |

### 流 43: `192.168.226.54:9071 <-> 120.53.53.53:443`

握手消息数: 6, 应用数据包数: 8

| # | 方向 | 类型 | 名称 | SNI | Cipher Suites | Cipher Suite | ALPN | Supported Groups | Signature Algorithms |
|---|------|------|------|-----|---------------|--------------|------|------------------|---------------------|
| 1 | 192.168.226.54:9071 -> 120.53.53.53:443 | 1 | ClientHello | - | 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc009, 0xc013, 0xc00a, 0xc01... | - | http/1.1, h2 | 0x001d, 0x0017, 0x0018, 0x0019 | 0x0804, 0x0403, 0x0807, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0503, 0x0603, 0x0201, 0x0203 |
| 2 | 120.53.53.53:443 -> 192.168.226.54:9071 | 2 | ServerHello | - | - | 0xc02b | h2 | - | - |
| 3 | 120.53.53.53:443 -> 192.168.226.54:9071 | 11 | Certificate | - | - | - | - | - | - |
| 4 | 120.53.53.53:443 -> 192.168.226.54:9071 | 12 | ServerKeyExchange | - | - | - | - | - | - |
| 5 | 120.53.53.53:443 -> 192.168.226.54:9071 | 14 | ServerHelloDone | - | - | - | - | - | - |
| 6 | 192.168.226.54:9071 -> 120.53.53.53:443 | 16 | ClientKeyExchange | - | - | - | - | - | - |

**证书链 (3 张证书):**

**证书 1:**

- Subject: `C=CN, ST=Guangdong Sheng, O=Tencent Technology(shenzhen)Company Limited, CN=120.53.53.53`
- Issuer: `C=CN, O=TrustAsia Technologies, Inc., CN=TrustAsia ECC OV TLS CA G3`
- Serial: `0xc6b5597f7adb6642c93b31666567ac1d`
- Not Before: `2024-11-19T00:00:00+00:00`
- Not After: `2025-12-19T23:59:59+00:00`
- SHA-256: `edef5e6bf8669289acd70e59fec9bc7d9962492af8699858403fa222482a2bbc`

**证书 2:**

- Subject: `C=CN, O=TrustAsia Technologies, Inc., CN=TrustAsia ECC OV TLS CA G3`
- Issuer: `C=US, ST=New Jersey, L=Jersey City, O=The USERTRUST Network, CN=USERTrust ECC Certification Authority`
- Serial: `0x4df7309184c7b632b600b5d4a045e959`
- Not Before: `2022-04-20T00:00:00+00:00`
- Not After: `2032-04-19T23:59:59+00:00`
- SHA-256: `397808dab0765b2d224831fcd34bfe56a4093f14c48a700727bb31a7ad420cb4`

**证书 3:**

- Subject: `C=US, ST=New Jersey, L=Jersey City, O=The USERTRUST Network, CN=USERTrust ECC Certification Authority`
- Issuer: `C=GB, ST=Greater Manchester, L=Salford, O=Comodo CA Limited, CN=AAA Certificate Services`
- Serial: `0x56671d04ea4f994c6f10814759d27594`
- Not Before: `2019-03-12T00:00:00+00:00`
- Not After: `2028-12-31T23:59:59+00:00`
- SHA-256: `a6cf64dbb4c8d5fd19ce48896068db03b533a8d1336c6256a87d00cbb3def3ea`

### 流 44: `192.168.226.54:9080 <-> 111.13.142.55:443`

握手消息数: 7, 应用数据包数: 8

| # | 方向 | 类型 | 名称 | SNI | Cipher Suites | Cipher Suite | ALPN | Supported Groups | Signature Algorithms |
|---|------|------|------|-----|---------------|--------------|------|------------------|---------------------|
| 1 | 192.168.226.54:9080 -> 111.13.142.55:443 | 1 | ClientHello | tracking.miui.com | 0x1302, 0x1301, 0xc02c, 0xc02b, 0xc030, 0xc02f, 0xc024, 0xc023, 0xc028, 0xc02... | - | h2, http/1.1 | 0x001d, 0x0017, 0x0018 | 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0201, 0x0403, 0x0503, 0x0203, 0x0202, 0x0601, 0x0603 |
| 2 | 111.13.142.55:443 -> 192.168.226.54:9080 | 2 | ServerHello | - | - | 0xc02f | h2 | - | - |
| 3 | 111.13.142.55:443 -> 192.168.226.54:9080 | 11 | Certificate | - | - | - | - | - | - |
| 4 | 111.13.142.55:443 -> 192.168.226.54:9080 | 12 | ServerKeyExchange | - | - | - | - | - | - |
| 5 | 111.13.142.55:443 -> 192.168.226.54:9080 | 14 | ServerHelloDone | - | - | - | - | - | - |
| 6 | 192.168.226.54:9080 -> 111.13.142.55:443 | 16 | ClientKeyExchange | - | - | - | - | - | - |
| 7 | 111.13.142.55:443 -> 192.168.226.54:9080 | 4 | NewSessionTicket | - | - | - | - | - | - |

**证书链 (2 张证书):**

**证书 1:**

- Subject: `CN=*.miui.com`
- Issuer: `C=US, O=DigiCert Inc, OU=www.digicert.com, CN=Encryption Everywhere DV TLS CA - G1`
- Serial: `0x1fe1eb19b229903608487f29a520727`
- Not Before: `2024-11-08T00:00:00+00:00`
- Not After: `2025-11-07T23:59:59+00:00`
- SHA-256: `5a6a03ba54f5fd218bb6ee124f1618d3a3f8bd824be58292835ee80e690619e1`

**证书 2:**

- Subject: `C=US, O=DigiCert Inc, OU=www.digicert.com, CN=Encryption Everywhere DV TLS CA - G1`
- Issuer: `C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert Global Root CA`
- Serial: `0x279ac458bc1b245abf98053cd2c9bb1`
- Not Before: `2017-11-27T12:46:10+00:00`
- Not After: `2027-11-27T12:46:10+00:00`
- SHA-256: `15eb0a75c673abfbdcd2fafc02823c91fe6cbc36e00788442c8754d72bec3717`

### 流 45: `192.168.226.54:9095 <-> 111.13.142.55:443`

握手消息数: 7, 应用数据包数: 8

| # | 方向 | 类型 | 名称 | SNI | Cipher Suites | Cipher Suite | ALPN | Supported Groups | Signature Algorithms |
|---|------|------|------|-----|---------------|--------------|------|------------------|---------------------|
| 1 | 192.168.226.54:9095 -> 111.13.142.55:443 | 1 | ClientHello | tracking.miui.com | 0x1302, 0x1301, 0xc02c, 0xc02b, 0xc030, 0xc02f, 0xc024, 0xc023, 0xc028, 0xc02... | - | h2, http/1.1 | 0x001d, 0x0017, 0x0018 | 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0201, 0x0403, 0x0503, 0x0203, 0x0202, 0x0601, 0x0603 |
| 2 | 111.13.142.55:443 -> 192.168.226.54:9095 | 2 | ServerHello | - | - | 0xc02f | h2 | - | - |
| 3 | 111.13.142.55:443 -> 192.168.226.54:9095 | 11 | Certificate | - | - | - | - | - | - |
| 4 | 111.13.142.55:443 -> 192.168.226.54:9095 | 12 | ServerKeyExchange | - | - | - | - | - | - |
| 5 | 111.13.142.55:443 -> 192.168.226.54:9095 | 14 | ServerHelloDone | - | - | - | - | - | - |
| 6 | 192.168.226.54:9095 -> 111.13.142.55:443 | 16 | ClientKeyExchange | - | - | - | - | - | - |
| 7 | 111.13.142.55:443 -> 192.168.226.54:9095 | 4 | NewSessionTicket | - | - | - | - | - | - |

**证书链 (2 张证书):**

**证书 1:**

- Subject: `CN=*.miui.com`
- Issuer: `C=US, O=DigiCert Inc, OU=www.digicert.com, CN=Encryption Everywhere DV TLS CA - G1`
- Serial: `0x1fe1eb19b229903608487f29a520727`
- Not Before: `2024-11-08T00:00:00+00:00`
- Not After: `2025-11-07T23:59:59+00:00`
- SHA-256: `5a6a03ba54f5fd218bb6ee124f1618d3a3f8bd824be58292835ee80e690619e1`

**证书 2:**

- Subject: `C=US, O=DigiCert Inc, OU=www.digicert.com, CN=Encryption Everywhere DV TLS CA - G1`
- Issuer: `C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert Global Root CA`
- Serial: `0x279ac458bc1b245abf98053cd2c9bb1`
- Not Before: `2017-11-27T12:46:10+00:00`
- Not After: `2027-11-27T12:46:10+00:00`
- SHA-256: `15eb0a75c673abfbdcd2fafc02823c91fe6cbc36e00788442c8754d72bec3717`

### 流 46: `192.168.226.54:9102 <-> 111.13.142.55:443`

握手消息数: 7, 应用数据包数: 8

| # | 方向 | 类型 | 名称 | SNI | Cipher Suites | Cipher Suite | ALPN | Supported Groups | Signature Algorithms |
|---|------|------|------|-----|---------------|--------------|------|------------------|---------------------|
| 1 | 192.168.226.54:9102 -> 111.13.142.55:443 | 1 | ClientHello | tracking.miui.com | 0x1302, 0x1301, 0xc02c, 0xc02b, 0xc030, 0xc02f, 0xc024, 0xc023, 0xc028, 0xc02... | - | h2, http/1.1 | 0x001d, 0x0017, 0x0018 | 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0201, 0x0403, 0x0503, 0x0203, 0x0202, 0x0601, 0x0603 |
| 2 | 111.13.142.55:443 -> 192.168.226.54:9102 | 2 | ServerHello | - | - | 0xc02f | h2 | - | - |
| 3 | 111.13.142.55:443 -> 192.168.226.54:9102 | 11 | Certificate | - | - | - | - | - | - |
| 4 | 111.13.142.55:443 -> 192.168.226.54:9102 | 12 | ServerKeyExchange | - | - | - | - | - | - |
| 5 | 111.13.142.55:443 -> 192.168.226.54:9102 | 14 | ServerHelloDone | - | - | - | - | - | - |
| 6 | 192.168.226.54:9102 -> 111.13.142.55:443 | 16 | ClientKeyExchange | - | - | - | - | - | - |
| 7 | 111.13.142.55:443 -> 192.168.226.54:9102 | 4 | NewSessionTicket | - | - | - | - | - | - |

**证书链 (2 张证书):**

**证书 1:**

- Subject: `CN=*.miui.com`
- Issuer: `C=US, O=DigiCert Inc, OU=www.digicert.com, CN=Encryption Everywhere DV TLS CA - G1`
- Serial: `0x1fe1eb19b229903608487f29a520727`
- Not Before: `2024-11-08T00:00:00+00:00`
- Not After: `2025-11-07T23:59:59+00:00`
- SHA-256: `5a6a03ba54f5fd218bb6ee124f1618d3a3f8bd824be58292835ee80e690619e1`

**证书 2:**

- Subject: `C=US, O=DigiCert Inc, OU=www.digicert.com, CN=Encryption Everywhere DV TLS CA - G1`
- Issuer: `C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert Global Root CA`
- Serial: `0x279ac458bc1b245abf98053cd2c9bb1`
- Not Before: `2017-11-27T12:46:10+00:00`
- Not After: `2027-11-27T12:46:10+00:00`
- SHA-256: `15eb0a75c673abfbdcd2fafc02823c91fe6cbc36e00788442c8754d72bec3717`

### 流 47: `192.168.226.54:9117 <-> 111.13.142.55:443`

握手消息数: 7, 应用数据包数: 8

| # | 方向 | 类型 | 名称 | SNI | Cipher Suites | Cipher Suite | ALPN | Supported Groups | Signature Algorithms |
|---|------|------|------|-----|---------------|--------------|------|------------------|---------------------|
| 1 | 192.168.226.54:9117 -> 111.13.142.55:443 | 1 | ClientHello | tracking.miui.com | 0x1302, 0x1301, 0xc02c, 0xc02b, 0xc030, 0xc02f, 0xc024, 0xc023, 0xc028, 0xc02... | - | h2, http/1.1 | 0x001d, 0x0017, 0x0018 | 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0201, 0x0403, 0x0503, 0x0203, 0x0202, 0x0601, 0x0603 |
| 2 | 111.13.142.55:443 -> 192.168.226.54:9117 | 2 | ServerHello | - | - | 0xc02f | h2 | - | - |
| 3 | 111.13.142.55:443 -> 192.168.226.54:9117 | 11 | Certificate | - | - | - | - | - | - |
| 4 | 111.13.142.55:443 -> 192.168.226.54:9117 | 12 | ServerKeyExchange | - | - | - | - | - | - |
| 5 | 111.13.142.55:443 -> 192.168.226.54:9117 | 14 | ServerHelloDone | - | - | - | - | - | - |
| 6 | 192.168.226.54:9117 -> 111.13.142.55:443 | 16 | ClientKeyExchange | - | - | - | - | - | - |
| 7 | 111.13.142.55:443 -> 192.168.226.54:9117 | 4 | NewSessionTicket | - | - | - | - | - | - |

**证书链 (2 张证书):**

**证书 1:**

- Subject: `CN=*.miui.com`
- Issuer: `C=US, O=DigiCert Inc, OU=www.digicert.com, CN=Encryption Everywhere DV TLS CA - G1`
- Serial: `0x1fe1eb19b229903608487f29a520727`
- Not Before: `2024-11-08T00:00:00+00:00`
- Not After: `2025-11-07T23:59:59+00:00`
- SHA-256: `5a6a03ba54f5fd218bb6ee124f1618d3a3f8bd824be58292835ee80e690619e1`

**证书 2:**

- Subject: `C=US, O=DigiCert Inc, OU=www.digicert.com, CN=Encryption Everywhere DV TLS CA - G1`
- Issuer: `C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert Global Root CA`
- Serial: `0x279ac458bc1b245abf98053cd2c9bb1`
- Not Before: `2017-11-27T12:46:10+00:00`
- Not After: `2027-11-27T12:46:10+00:00`
- SHA-256: `15eb0a75c673abfbdcd2fafc02823c91fe6cbc36e00788442c8754d72bec3717`

## Native vs tshark 对比结果

总计 47 个流, 其中 47 个一致, 0 个不一致。

| 流 | 结果 | 差异说明 |
|-----|------|---------|
| `192.168.226.54:8975 <-> 1.12.12.21:853` | PASS (一致) | - |
| `192.168.226.54:8907 <-> 111.13.142.55:443` | PASS (一致) | - |
| `192.168.226.54:8922 <-> 111.13.142.55:443` | PASS (一致) | - |
| `192.168.226.54:9008 <-> 111.13.142.55:443` | PASS (一致) | - |
| `192.168.226.54:9052 <-> 111.13.142.55:443` | PASS (一致) | - |
| `192.168.226.54:9080 <-> 111.13.142.55:443` | PASS (一致) | - |
| `192.168.226.54:9095 <-> 111.13.142.55:443` | PASS (一致) | - |
| `192.168.226.54:9102 <-> 111.13.142.55:443` | PASS (一致) | - |
| `192.168.226.54:9117 <-> 111.13.142.55:443` | PASS (一致) | - |
| `192.168.226.54:8018 <-> 111.31.204.105:443` | PASS (一致) | - |
| `192.168.226.54:7700 <-> 120.53.53.53:443` | PASS (一致) | - |
| `192.168.226.54:7707 <-> 120.53.53.53:443` | PASS (一致) | - |
| `192.168.226.54:9063 <-> 120.53.53.53:443` | PASS (一致) | - |
| `192.168.226.54:9064 <-> 120.53.53.53:443` | PASS (一致) | - |
| `192.168.226.54:9068 <-> 120.53.53.53:443` | PASS (一致) | - |
| `192.168.226.54:9071 <-> 120.53.53.53:443` | PASS (一致) | - |
| `192.168.226.54:8932 <-> 120.53.53.53:853` | PASS (一致) | - |
| `192.168.226.54:8938 <-> 120.53.53.53:853` | PASS (一致) | - |
| `192.168.226.54:8967 <-> 120.53.53.53:853` | PASS (一致) | - |
| `192.168.226.54:8926 <-> 20.50.73.13:443` | PASS (一致) | - |
| `192.168.226.54:8927 <-> 223.5.5.5:443` | PASS (一致) | - |
| `192.168.226.54:8928 <-> 223.5.5.5:443` | PASS (一致) | - |
| `192.168.226.54:8929 <-> 223.6.6.6:853` | PASS (一致) | - |
| `192.168.226.54:8930 <-> 223.5.5.5:853` | PASS (一致) | - |
| `192.168.226.54:8931 <-> 223.6.6.6:443` | PASS (一致) | - |
| `192.168.226.54:8933 <-> 223.5.5.5:853` | PASS (一致) | - |
| `192.168.226.54:8934 <-> 223.6.6.6:853` | PASS (一致) | - |
| `192.168.226.54:8935 <-> 223.5.5.5:853` | PASS (一致) | - |
| `192.168.226.54:8936 <-> 223.6.6.6:853` | PASS (一致) | - |
| `192.168.226.54:8937 <-> 223.6.6.6:443` | PASS (一致) | - |
| `192.168.226.54:8963 <-> 20.42.73.25:443` | PASS (一致) | - |
| `192.168.226.54:8964 <-> 223.5.5.5:443` | PASS (一致) | - |
| `192.168.226.54:8965 <-> 223.5.5.5:443` | PASS (一致) | - |
| `192.168.226.54:8966 <-> 223.6.6.6:443` | PASS (一致) | - |
| `192.168.226.54:8968 <-> 223.6.6.6:853` | PASS (一致) | - |
| `192.168.226.54:8969 <-> 223.5.5.5:853` | PASS (一致) | - |
| `192.168.226.54:8970 <-> 223.6.6.6:853` | PASS (一致) | - |
| `192.168.226.54:8971 <-> 223.6.6.6:853` | PASS (一致) | - |
| `192.168.226.54:8972 <-> 223.5.5.5:853` | PASS (一致) | - |
| `192.168.226.54:8973 <-> 223.6.6.6:443` | PASS (一致) | - |
| `192.168.226.54:8974 <-> 223.5.5.5:853` | PASS (一致) | - |
| `192.168.226.54:9060 <-> 223.5.5.5:443` | PASS (一致) | - |
| `192.168.226.54:9061 <-> 223.5.5.5:443` | PASS (一致) | - |
| `192.168.226.54:9062 <-> 223.5.5.5:443` | PASS (一致) | - |
| `192.168.226.54:9065 <-> 223.5.5.5:443` | PASS (一致) | - |
| `192.168.226.54:9069 <-> 223.5.5.5:443` | PASS (一致) | - |
| `192.168.226.54:9070 <-> 223.5.5.5:443` | PASS (一致) | - |

所有流的 TLS 握手信息在 native 引擎和 tshark 之间完全一致。
