import pandas as pd

def generate_report(log_file="data/logs/capture.pcap", output_file="data/logs/report.csv"):
    df = pd.read_csv(log_file)
    df.to_csv(output_file, index=False)
    print(f"Report saved: {output_file}")
