import pandas as pd
import numpy as np

try:
    from nfstream import NFStreamer
    NFSTREAM_AVAILABLE = True
except ImportError:
    NFSTREAM_AVAILABLE = False

# Mapping nfstream features to CICIDS2017 features where possible
# This is a simplified best-effort mapping. Accurate reproduction of CICIDS2017 
# features requires the Java-based CICFlowMeter.
def extract_features_from_pcap(pcap_path):
    if not NFSTREAM_AVAILABLE:
        raise RuntimeError("nfstream is not installed. Please install it using 'pip install nfstream' to enable pcap processing.")
        
    streamer = NFStreamer(source=pcap_path, statistical_analysis=True)
    
    records = []
    for flow in streamer:
        # Mapping attributes to CICIDS2017 features (approximation)
        f = {}
        f['Destination Port'] = flow.dst_port
        f['Flow Duration'] = flow.bidirectional_duration_ms * 1000  # ms to microseconds
        
        # Packets and bytes
        f['Total Fwd Packets'] = flow.src2dst_packets
        f['Total Backward Packets'] = flow.dst2src_packets
        f['Total Length of Fwd Packets'] = flow.src2dst_bytes
        f['Total Length of Bwd Packets'] = flow.dst2src_bytes
        
        # Packet length stats
        f['Fwd Packet Length Max'] = flow.src2dst_max_ps
        f['Fwd Packet Length Min'] = flow.src2dst_min_ps
        f['Fwd Packet Length Mean'] = flow.src2dst_mean_ps
        f['Fwd Packet Length Std'] = flow.src2dst_stddev_ps
        
        f['Bwd Packet Length Max'] = flow.dst2src_max_ps
        f['Bwd Packet Length Min'] = flow.dst2src_min_ps
        f['Bwd Packet Length Mean'] = flow.dst2src_mean_ps
        f['Bwd Packet Length Std'] = flow.dst2src_stddev_ps
        
        # Additional approximations (Fill with zeros for those not directly available in nfstream)
        # Note: A real implementation would implement all 78 specific statistics. 
        # Here we provide the fundamental mapping and zero pad the rest.
        records.append(f)
        
    df = pd.DataFrame(records)
    # The utils.preprocess_data function will pad missing columns with zeros.
    return df
