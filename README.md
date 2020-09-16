# Wireless monitor

### Requirements

    ***cap2hccapx*** from [hashcat-utils](https://github.com/hashcat/hashcat-utils).

### How to use

```bash
# Create new monitor interface, if not exists

python app.py -i wlan0 -m mon0

# Enable interface if not enabled
python app.py -u mon0

# Start sniffing on interface  
python app.py -s -i mon0 -c 1

# Export captured packets to pcap file
python app.py -e db.pcap

```