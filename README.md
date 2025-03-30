# Jina: Network Intrusion Detection System (NIDS)

A Python-based network intrusion detection system that can identify various network attacks and anomalies.

## Features

- Real-time network packet capture and analysis
- Signature-based detection for known attack patterns
- Anomaly-based detection using machine learning
- GUI dashboard with real-time traffic visualization
- Customizable alert system
- Detailed attack reports and statistics
- Rule-based detection engine
- Export capability for logs and reports

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/nids_project.git
   cd nids_project
   ```

2. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

3. Run the application:
   ```
   python main.py
   ```

## Usage

### GUI Mode

Simply run the application without any arguments to launch the GUI:
```
python main.py
```

### Console Mode

Run the application with the `--no-gui` flag for headless operation:
```
python main.py --no-gui
```

### Configuration

You can provide a custom configuration file:
```
python main.py --config my_config.json
```

### Debug Mode

Enable debug logging with:
```
python main.py --debug
```

## System Requirements

- Python 3.8 or higher
- Administrative/root privileges (for packet capture)
- Network interface in promiscuous mode (for monitoring network traffic)

## License

This project is licensed under the MIT License - see the LICENSE file for details.