import dpkt
import socket
import pygeoip
from collections import Counter, defaultdict

geo_ip_db = pygeoip.GeoIP('GeoLiteCity.dat')

def createKML(target_ip):
    target_location = geo_ip_db.record_by_name(target_ip)
    source_location = geo_ip_db.record_by_name('134.197.0.24')
    try:
        target_long = target_location['longitude']
        target_lat = target_location['latitude']
        source_long = source_location['longitude']
        source_lat = source_location['latitude']
        kml_markup = (
            '<Placemark>\n'
            '<name>%s</name>\n'
            '<extrude>1</extrude>\n'
            '<tessellate>1</tessellate>\n'
            '<styleUrl>#transBluePoly</styleUrl>\n'
            '<LineString>\n'
            '<coordinates>%6f,%6f\n%6f,%6f</coordinates>\n'
            '</LineString>\n'
            '</Placemark>\n'
        ) % (target_ip, target_long, target_lat, source_long, source_lat)
        return kml_markup
    except:
        return ''

def generateKMLPoints(packet_data):
    kml_points = ''
    for timestamp, buffer in packet_data:
        try:
            ethernet_frame = dpkt.ethernet.Ethernet(buffer)
            ip_packet = ethernet_frame.data
            destination_address = socket.inet_ntoa(ip_packet.dst)
            kml_line = createKML(destination_address)
            kml_points += kml_line
        except:
            continue
    return kml_points

def analyzePackets(pcap):
    stats = {
        'packet_count': 0,
        'protocol_distribution': Counter(),
        'total_bytes': 0,
        'traffic_flows': defaultdict(int)  # To record traffic flow
    }
    start_time = end_time = None

    for timestamp, buffer in pcap:
        if start_time is None:
            start_time = timestamp
        end_time = timestamp

        stats['packet_count'] += 1
        stats['total_bytes'] += len(buffer)

        try:
            ethernet_frame = dpkt.ethernet.Ethernet(buffer)
            ip_packet = ethernet_frame.data
            stats['protocol_distribution'][ip_packet.p] += 1

            src_ip = socket.inet_ntoa(ip_packet.src)
            dst_ip = socket.inet_ntoa(ip_packet.dst)
            stats['traffic_flows'][(src_ip, dst_ip)] += len(buffer)
        except:
            continue

    duration = end_time - start_time if start_time and end_time else 1
    stats['data_rate'] = stats['total_bytes'] / duration  # bytes per second

    return stats

def writeStatsToFile(stats, filename='network_stats.txt'):
    with open(filename, 'w') as file:
        file.write(f"Total Packets: {stats['packet_count']}\n")
        file.write(f"Total Bytes: {stats['total_bytes']}\n")
        file.write(f"Data Rate: {stats['data_rate']} bytes/sec\n")
        file.write("Protocol Distribution:\n")
        for protocol, count in stats['protocol_distribution'].items():
            file.write(f"Protocol {protocol}: {count}\n")
        file.write("Traffic Flows:\n")
        for (src, dst), bytes in stats['traffic_flows'].items():
            file.write(f"From {src} to {dst}: {bytes} bytes\n")

def main():
    pcap_file = open('wireshark-info.pcap', 'rb')
    pcap_reader = dpkt.pcap.Reader(pcap_file)

    kml_header = '<?xml version="1.0" encoding="UTF-8"?>\n<kml xmlns="http://www.opengis.net/kml/2.2">\n<Document>\n'\
                 '<Style id="transBluePoly">' \
                 '<LineStyle>' \
                 '<width>1.5</width>' \
                 '<color>501400E6</color>' \
                 '</LineStyle>' \
                 '</Style>'
    kml_footer = '</Document>\n</kml>\n'
    kml_document = kml_header + generateKMLPoints(pcap_reader) + kml_footer

    with open('output.kml', 'w') as kml_output:
        kml_output.write(kml_document)
    
    pcap_file.seek(0)  
    pcap_file.close()

    # Write statistics to a file
    pcap_file1 = open('wireshark-info.pcap', 'rb')
    pcap_reader1 = dpkt.pcap.Reader(pcap_file1)

    stats = analyzePackets(pcap_reader1)
    writeStatsToFile(stats)  

    pcap_file.close()

if __name__ == '__main__':
    main()
