# Tailscale Monitor

A web-based monitoring application for your Tailscale network. This tool provides real-time monitoring and visualization of your Tailscale network status, connections, and performance metrics.
![Uploading image.png…]()

## Prerequisites

- Python 3.9+
- A running Tailscale installation on your machine
- `pip` package manager

## Installation

1. Clone this repository:
```bash
git clone https://github.com/michael20779/tailscale-monitor.git
cd tailscale-monitor
```

2. Create and activate a virtual environment (recommended):
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

Run the application:
```bash
python tailscale_monitor.py
```

The application will be available at `http://localhost:5000`

## Features

- Real-time monitoring of Tailscale network status
- Connection statistics and latency measurements
- Network topology visualization
- Performance metrics and graphs
- Peer connection status
- IP address and routing information

## Configuration

The application automatically detects your Tailscale interface and configuration. No additional configuration is typically needed.


## Contributing

Contributions are welcome! Please feel free to submit a Pull Request
