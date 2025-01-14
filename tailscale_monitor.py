#!/usr/bin/env python3

import subprocess
import time
import json
import psutil
import datetime
import threading
import collections
import ipaddress
import requests
import re
import socket
from ping3 import ping
from flask import Flask, render_template, jsonify
from threading import Thread
import numpy as np

app = Flask(__name__)
monitor = None

class TailscaleMonitor:
    def __init__(self):
        self.interface = self._get_tailscale_interface()
        self.current_stats = None
        self.prev_stats = None
        self.last_update = None
        self.monitoring = True
        self.history_size = 3600  # Store 1 hour of data (1 sample per second)
        self.history = {
            'timestamps': collections.deque(maxlen=self.history_size),
            'upload_rates': collections.deque(maxlen=self.history_size),
            'download_rates': collections.deque(maxlen=self.history_size),
            'latencies': collections.deque(maxlen=self.history_size),
            'cpu_usage': collections.deque(maxlen=self.history_size),
            'memory_usage': collections.deque(maxlen=self.history_size),
            'packet_loss': collections.deque(maxlen=self.history_size),
            'jitter': collections.deque(maxlen=self.history_size),
            'connection_events': collections.deque(maxlen=100)  # Store last 100 connection events
        }
        self.alert_thresholds = {
            'latency': 200,  # ms
            'cpu': 80,  # percent
            'memory': 80,  # percent
            'bandwidth': 1024 * 1024 * 100,  # 100 MB/s
            'packet_loss': 5,  # percent
            'jitter': 50  # ms
        }
        self.peer_status = {}  # Track peer connection status
        Thread(target=self._update_stats_loop).start()
        Thread(target=self._monitor_peer_status).start()
        
    def _get_tailscale_interface(self):
        """Find the Tailscale network interface."""
        for interface, _ in psutil.net_if_addrs().items():
            if interface.startswith(('tailscale', 'ts')):
                return interface
        raise Exception("Tailscale interface not found. Make sure Tailscale is running.")

    def get_network_stats(self):
        """Get current network statistics for the Tailscale interface."""
        net_io = psutil.net_io_counters(pernic=True).get(self.interface)
        if not net_io:
            return None
        
        return {
            'bytes_sent': net_io.bytes_sent,
            'bytes_recv': net_io.bytes_recv,
            'packets_sent': net_io.packets_sent,
            'packets_recv': net_io.packets_recv
        }

    def get_system_resources(self):
        """Get system resource usage."""
        cpu_percent = psutil.cpu_percent(interval=None)
        memory = psutil.virtual_memory()
        return {
            'cpu_percent': cpu_percent,
            'memory_percent': memory.percent,
            'memory_used': self.format_bytes(memory.used),
            'memory_total': self.format_bytes(memory.total)
        }

    def get_peer_latency(self, peer_ip):
        """Get latency to a peer."""
        try:
            latency = ping(peer_ip, timeout=1)
            return round(latency * 1000) if latency else None  # Convert to ms
        except Exception:
            return None

    def get_peer_location(self, ip):
        """Get geolocation info for an IP address."""
        try:
            response = requests.get(f"https://ipapi.co/{ip}/json/")
            if response.status_code == 200:
                data = response.json()
                return {
                    'country': data.get('country_name', 'Unknown'),
                    'city': data.get('city', 'Unknown'),
                    'region': data.get('region', 'Unknown')
                }
        except Exception:
            pass
        return {'country': 'Unknown', 'city': 'Unknown', 'region': 'Unknown'}

    def get_connected_peers(self):
        """Get information about connected Tailscale peers."""
        try:
            result = subprocess.run(['tailscale', 'status', '--json'], 
                                 capture_output=True, text=True, check=True)
            try:
                status_data = json.loads(result.stdout)
                peers = []
                
                # Process peer information from JSON output
                for peer_id, peer_info in status_data.get('Peer', {}).items():
                    if peer_info.get('Online', False):  # Only include online peers
                        peer_ips = peer_info.get('TailscaleIPs', [])
                        if peer_ips:
                            peer_ip = peer_ips[0]  # Use the first Tailscale IP
                            try:
                                latency = self.get_peer_latency(peer_ip)
                                location = self.get_peer_location(peer_ip)
                                peers.append({
                                    'name': peer_info.get('HostName', 'Unknown'),
                                    'ip': peer_ip,
                                    'latency': f"{latency}ms" if latency else "N/A",
                                    'location': location,
                                    'os': peer_info.get('OS', 'Unknown'),
                                    'version': peer_info.get('Version', 'Unknown')
                                })
                            except Exception as e:
                                print(f"Error processing peer {peer_ip}: {str(e)}")
                                continue
                
                return peers
            except json.JSONDecodeError:
                # Fallback to text parsing if JSON fails
                print("JSON parsing failed, falling back to text output")
                result = subprocess.run(['tailscale', 'status'], 
                                     capture_output=True, text=True, check=True)
                peers = []
                for line in result.stdout.strip().split('\n')[1:]:  # Skip header
                    try:
                        parts = line.split()
                        if len(parts) >= 2:
                            peer_ip = parts[1]
                            if ipaddress.ip_address(peer_ip):  # Validate IP
                                latency = self.get_peer_latency(peer_ip)
                                location = self.get_peer_location(peer_ip)
                                peers.append({
                                    'name': parts[0],
                                    'ip': peer_ip,
                                    'latency': f"{latency}ms" if latency else "N/A",
                                    'location': location
                                })
                    except (ValueError, IndexError) as e:
                        print(f"Error parsing line '{line}': {str(e)}")
                        continue
                return peers
        except subprocess.CalledProcessError as e:
            print(f"Error running tailscale command: {str(e)}")
            print(f"Error output: {e.stderr}")
            return []
        except Exception as e:
            print(f"Unexpected error in get_connected_peers: {str(e)}")
            return []

    def format_bytes(self, bytes):
        """Convert bytes to human readable format."""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes < 1024:
                return f"{bytes:.2f} {unit}"
            bytes /= 1024
        return f"{bytes:.2f} TB"

    def check_alerts(self, stats, resources):
        """Check for all types of alerts."""
        all_alerts = []
        
        # Get bandwidth alerts
        bandwidth_alerts = self.get_bandwidth_alerts(
            stats.get('bytes_sent_rate', 0),
            stats.get('bytes_recv_rate', 0)
        )
        all_alerts.extend(bandwidth_alerts)
        
        # Get system alerts
        system_alerts = self.check_system_alerts(resources)
        all_alerts.extend(system_alerts)
        
        # Get peer alerts
        for peer in stats.get('peers', []):
            peer_alerts = self.get_peer_alerts(peer)
            all_alerts.extend(peer_alerts)
        
        return all_alerts

    def _update_stats_loop(self, interval=1):
        """Background loop to update statistics."""
        while self.monitoring:
            self.prev_stats = self.current_stats
            self.current_stats = self.get_network_stats()
            self.last_update = datetime.datetime.now()
            
            if self.current_stats and self.prev_stats:
                # Calculate rates
                bytes_sent_rate = (self.current_stats['bytes_sent'] - self.prev_stats['bytes_sent']) / interval
                bytes_recv_rate = (self.current_stats['bytes_recv'] - self.prev_stats['bytes_recv']) / interval
                
                # Update history
                self.history['timestamps'].append(self.last_update.strftime("%H:%M:%S"))
                self.history['upload_rates'].append(bytes_sent_rate)
                self.history['download_rates'].append(bytes_recv_rate)
                
                # Get and store system resources
                resources = self.get_system_resources()
                self.history['cpu_usage'].append(resources['cpu_percent'])
                self.history['memory_usage'].append(resources['memory_percent'])
                
                # Calculate and store average latency
                peers = self.get_connected_peers()
                latencies = [float(p['latency'].rstrip('ms')) for p in peers if p['latency'] != 'N/A']
                avg_latency = np.mean(latencies) if latencies else 0
                self.history['latencies'].append(avg_latency)
            
            time.sleep(interval)

    def get_current_data(self):
        """Get formatted current statistics for the web interface."""
        if not self.current_stats or not self.prev_stats:
            return None

        time_diff = 1  # 1 second update interval
        bytes_sent_rate = (self.current_stats['bytes_sent'] - self.prev_stats['bytes_sent']) / time_diff
        bytes_recv_rate = (self.current_stats['bytes_recv'] - self.prev_stats['bytes_recv']) / time_diff

        # Get system resources
        resources = self.get_system_resources()
        
        # Get peer information
        peers = self.get_connected_peers()
        
        # Calculate average latency
        latencies = [float(p['latency'].rstrip('ms')) for p in peers if p['latency'] != 'N/A']
        avg_latency = np.mean(latencies) if latencies else 0

        stats = {
            'timestamp': self.last_update.strftime("%Y-%m-%d %H:%M:%S"),
            'upload_rate': self.format_bytes(bytes_sent_rate) + '/s',
            'download_rate': self.format_bytes(bytes_recv_rate) + '/s',
            'total_upload': self.format_bytes(self.current_stats['bytes_sent']),
            'total_download': self.format_bytes(self.current_stats['bytes_recv']),
            'packets_sent': self.current_stats['packets_sent'],
            'packets_recv': self.current_stats['packets_recv'],
            'peers': peers,
            'avg_latency': f"{avg_latency:.1f}ms",
            'bytes_sent_rate': bytes_sent_rate,
            'bytes_recv_rate': bytes_recv_rate,
            'cpu_percent': resources['cpu_percent'],
            'memory_percent': resources['memory_percent'],
            'memory_used': resources['memory_used'],
            'memory_total': resources['memory_total'],
            'history': {
                'timestamps': list(self.history['timestamps']),
                'upload_rates': [float(x) for x in self.history['upload_rates']],
                'download_rates': [float(x) for x in self.history['download_rates']],
                'latencies': list(self.history['latencies']),
                'cpu_usage': list(self.history['cpu_usage']),
                'memory_usage': list(self.history['memory_usage'])
            },
            'network_quality': {
                peer['ip']: self.get_network_quality(peer['ip'])
                for peer in peers
            },
            'interface_details': self.get_interface_details(),
            'bandwidth_usage': self.get_bandwidth_usage(5),  # Last 5 minutes
            'connection_history': self.get_connection_history()
        }
        
        # Check for alerts
        stats['alerts'] = self.check_alerts(stats, resources)
        
        return stats

    def __del__(self):
        """Cleanup when the monitor is destroyed"""
        self.monitoring = False

    def get_network_quality(self, peer_ip):
        """Get detailed network quality metrics for a peer."""
        try:
            # Measure latency multiple times to calculate jitter
            latencies = []
            packet_loss = 0
            for _ in range(5):
                latency = ping(peer_ip, timeout=1)
                if latency:
                    latencies.append(latency * 1000)  # Convert to ms
                else:
                    packet_loss += 1

            if not latencies:
                return None

            # Calculate metrics
            avg_latency = np.mean(latencies)
            jitter = np.std(latencies) if len(latencies) > 1 else 0
            packet_loss_percent = (packet_loss / 5) * 100

            return {
                'avg_latency': f"{avg_latency:.1f}ms",
                'min_latency': f"{min(latencies):.1f}ms",
                'max_latency': f"{max(latencies):.1f}ms",
                'jitter': f"{jitter:.1f}ms",
                'packet_loss': f"{packet_loss_percent:.1f}%",
                'quality_score': self._calculate_quality_score(avg_latency, jitter, packet_loss_percent)
            }
        except Exception as e:
            print(f"Error measuring network quality for {peer_ip}: {str(e)}")
            return None

    def _calculate_quality_score(self, latency, jitter, packet_loss):
        """Calculate a network quality score (0-100)."""
        # Weight factors
        latency_weight = 0.4
        jitter_weight = 0.3
        packet_loss_weight = 0.3

        # Normalize metrics (higher score is better)
        latency_score = max(0, 100 - (latency / 2))  # 200ms -> 0, 0ms -> 100
        jitter_score = max(0, 100 - (jitter * 2))    # 50ms -> 0, 0ms -> 100
        packet_loss_score = max(0, 100 - (packet_loss * 20))  # 5% -> 0, 0% -> 100

        # Calculate weighted average
        quality_score = (latency_score * latency_weight +
                        jitter_score * jitter_weight +
                        packet_loss_score * packet_loss_weight)

        return round(quality_score)

    def get_interface_details(self):
        """Get detailed information about the Tailscale interface."""
        try:
            interface_info = psutil.net_if_addrs()[self.interface]
            interface_stats = psutil.net_if_stats()[self.interface]
            
            addresses = []
            for addr in interface_info:
                addr_info = {
                    'family': str(addr.family),
                    'address': addr.address,
                    'netmask': addr.netmask,
                    'broadcast': addr.broadcast
                }
                addresses.append(addr_info)

            return {
                'name': self.interface,
                'addresses': addresses,
                'is_up': interface_stats.isup,
                'speed': f"{interface_stats.speed}Mb/s" if interface_stats.speed > 0 else "Unknown",
                'mtu': interface_stats.mtu,
                'duplex': interface_stats.duplex,
                'features': self._get_interface_features()
            }
        except Exception as e:
            print(f"Error getting interface details: {str(e)}")
            return None

    def _get_interface_features(self):
        """Get supported features of the Tailscale interface."""
        try:
            # Run ethtool or similar command to get interface features
            result = subprocess.run(['ethtool', '-k', self.interface], 
                                 capture_output=True, text=True)
            if result.returncode == 0:
                features = {}
                for line in result.stdout.split('\n'):
                    if ':' in line:
                        feature, value = line.split(':')
                        features[feature.strip()] = value.strip()
                return features
        except Exception:
            pass
        return None

    def get_bandwidth_usage(self, interval_minutes=5):
        """Get bandwidth usage statistics over the specified interval."""
        try:
            now = datetime.datetime.now()
            interval_start = now - datetime.timedelta(minutes=interval_minutes)
            
            # Get data points within the interval
            data_points = list(zip(
                self.history['timestamps'],
                self.history['upload_rates'],
                self.history['download_rates']
            ))
            
            # Filter data points within the interval
            interval_data = [
                (t, u, d) for t, u, d in data_points
                if datetime.datetime.strptime(t, "%H:%M:%S").replace(year=now.year, month=now.month, day=now.day) >= interval_start
            ]
            
            if not interval_data:
                return None
            
            # Calculate statistics
            upload_rates = [u for _, u, _ in interval_data]
            download_rates = [d for _, _, d in interval_data]
            
            return {
                'interval': f"{interval_minutes} minutes",
                'upload': {
                    'average': self.format_bytes(np.mean(upload_rates)) + '/s',
                    'peak': self.format_bytes(max(upload_rates)) + '/s',
                    'total': self.format_bytes(sum(upload_rates) / len(upload_rates) * interval_minutes * 60)
                },
                'download': {
                    'average': self.format_bytes(np.mean(download_rates)) + '/s',
                    'peak': self.format_bytes(max(download_rates)) + '/s',
                    'total': self.format_bytes(sum(download_rates) / len(download_rates) * interval_minutes * 60)
                }
            }
        except Exception as e:
            print(f"Error calculating bandwidth usage: {str(e)}")
            return None

    def _monitor_peer_status(self):
        """Monitor peer connection status changes."""
        while self.monitoring:
            try:
                current_peers = {peer['ip']: peer for peer in self.get_connected_peers()}
                
                # Check for status changes
                for ip, peer in current_peers.items():
                    if ip not in self.peer_status:
                        # New peer connected
                        self._record_connection_event(peer, 'connected')
                    elif self._has_status_changed(self.peer_status[ip], peer):
                        # Peer status changed
                        self._record_connection_event(peer, 'status_changed')
                
                for ip in list(self.peer_status.keys()):
                    if ip not in current_peers:
                        # Peer disconnected
                        self._record_connection_event(self.peer_status[ip], 'disconnected')
                
                # Update status cache
                self.peer_status = current_peers
                
            except Exception as e:
                print(f"Error monitoring peer status: {str(e)}")
            
            time.sleep(10)  # Check every 10 seconds

    def _has_status_changed(self, old_status, new_status):
        """Check if peer status has changed significantly."""
        return (
            old_status['latency'] != new_status['latency'] or
            old_status['os'] != new_status['os'] or
            old_status['version'] != new_status['version']
        )

    def _record_connection_event(self, peer, event_type):
        """Record a peer connection event."""
        event = {
            'timestamp': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'peer_name': peer['name'],
            'peer_ip': peer['ip'],
            'event_type': event_type,
            'details': {
                'latency': peer['latency'],
                'os': peer['os'],
                'version': peer['version'],
                'location': peer['location']
            }
        }
        self.history['connection_events'].append(event)

    def get_connection_history(self):
        """Get the connection event history."""
        return list(self.history['connection_events'])

    def run_speed_test(self, peer_ip):
        """Run a network speed test to a specific peer using ICMP ping."""
        try:
            # Use ping to measure network performance instead of TCP
            # This avoids needing open ports on peers
            test_size = 1024  # bytes
            count = 10
            latencies = []
            
            for _ in range(count):
                start_time = time.time()
                result = ping(peer_ip, size=test_size, timeout=2)
                if result:
                    latencies.append(result)
                time.sleep(0.1)  # Small delay between pings
            
            if not latencies:
                return {
                    'error': 'Could not reach peer',
                    'timestamp': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                }
            
            # Calculate approximate bandwidth based on ping times
            avg_latency = np.mean(latencies)
            bandwidth = (test_size * 8) / (avg_latency * 1000)  # Mbps
            
            return {
                'estimated_bandwidth': f"{bandwidth:.2f} Mbps",
                'avg_latency': f"{avg_latency * 1000:.2f}ms",
                'packet_size': f"{test_size} bytes",
                'successful_tests': len(latencies),
                'total_tests': count,
                'timestamp': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
        except Exception as e:
            print(f"Error running speed test: {str(e)}")
            return None

    def check_route_quality(self, peer_ip):
        """Check route quality to a peer using ping with increasing TTL."""
        try:
            max_hops = 30
            hops = []
            
            for ttl in range(1, max_hops + 1):
                # Try to reach the target with increasing TTL
                latency = ping(peer_ip, ttl=ttl, timeout=1)
                
                if latency:
                    hop = {
                        'number': str(ttl),
                        'ip': peer_ip,
                        'latency': f"{latency * 1000:.1f}ms"
                    }
                    hops.append(hop)
                    break
                else:
                    # If we get here, the packet was dropped at this TTL
                    # Try to get the IP that dropped it using a separate ping
                    intermediate_latency = ping('1.1.1.1', ttl=ttl, timeout=1)
                    hop = {
                        'number': str(ttl),
                        'ip': 'Unknown',
                        'latency': f"{intermediate_latency * 1000:.1f}ms" if intermediate_latency else '*'
                    }
                    hops.append(hop)
            
            return {
                'hops': hops,
                'hop_count': len(hops),
                'timestamp': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
        except Exception as e:
            print(f"Error checking route quality: {str(e)}")
            return None

    def monitor_connection_stability(self, peer_ip, duration=300):
        """Monitor connection stability over a period."""
        try:
            start_time = time.time()
            end_time = start_time + duration
            
            ping_results = []
            while time.time() < end_time:
                latency = ping(peer_ip, timeout=1)
                timestamp = datetime.datetime.now()
                
                ping_results.append({
                    'timestamp': timestamp.strftime("%H:%M:%S"),
                    'latency': round(latency * 1000) if latency else None
                })
                
                time.sleep(1)
            
            # Calculate stability metrics
            successful_pings = [p for p in ping_results if p['latency'] is not None]
            failed_pings = [p for p in ping_results if p['latency'] is None]
            
            if ping_results:
                latencies = [p['latency'] for p in successful_pings if p['latency'] is not None]
                avg_latency = np.mean(latencies) if latencies else 0
                jitter = np.std(latencies) if len(latencies) > 1 else 0
                packet_loss = (len(failed_pings) / len(ping_results)) * 100
                
                return {
                    'duration': duration,
                    'avg_latency': f"{avg_latency:.1f}ms",
                    'min_latency': f"{min(latencies):.1f}ms" if latencies else "N/A",
                    'max_latency': f"{max(latencies):.1f}ms" if latencies else "N/A",
                    'jitter': f"{jitter:.1f}ms",
                    'packet_loss': f"{packet_loss:.1f}%",
                    'stability_score': self._calculate_stability_score(avg_latency, jitter, packet_loss),
                    'ping_history': ping_results
                }
        except Exception as e:
            print(f"Error monitoring connection stability: {str(e)}")
            return None

    def _calculate_stability_score(self, latency, jitter, packet_loss):
        """Calculate a stability score (0-100) based on connection metrics."""
        try:
            # Normalize metrics to 0-100 scale (higher is better)
            latency_score = max(0, 100 - (latency / 2))  # 200ms -> 0, 0ms -> 100
            jitter_score = max(0, 100 - (jitter * 2))    # 50ms -> 0, 0ms -> 100
            packet_loss_score = max(0, 100 - (packet_loss * 10))  # 10% -> 0, 0% -> 100
            
            # Weight factors
            latency_weight = 0.4
            jitter_weight = 0.3
            packet_loss_weight = 0.3
            
            # Calculate weighted score
            stability_score = (
                latency_score * latency_weight +
                jitter_score * jitter_weight +
                packet_loss_score * packet_loss_weight
            )
            
            return round(stability_score)
        except Exception as e:
            print(f"Error calculating stability score: {str(e)}")
            return 0

    def get_peer_performance_report(self, peer_ip):
        """Generate a comprehensive performance report for a peer."""
        try:
            report = {
                'timestamp': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'peer_ip': peer_ip
            }
            
            # Get basic network quality
            network_quality = self.get_network_quality(peer_ip)
            if network_quality:
                report['network_quality'] = network_quality
            
            # Run speed test
            speed_test = self.run_speed_test(peer_ip)
            if speed_test:
                report['speed_test'] = speed_test
            
            # Check route quality
            route_quality = self.check_route_quality(peer_ip)
            if route_quality:
                report['route_quality'] = route_quality
            
            # Monitor stability (30 seconds)
            stability = self.monitor_connection_stability(peer_ip, 30)
            if stability:
                report['stability'] = stability
            
            return report
        except Exception as e:
            print(f"Error generating performance report: {str(e)}")
            return None

    def set_alert_threshold(self, metric, value):
        """Set an alert threshold for a specific metric."""
        if metric in self.alert_thresholds:
            self.alert_thresholds[metric] = value
            return True
        return False

    def get_bandwidth_alerts(self, upload_rate, download_rate):
        """Check for bandwidth-related alerts."""
        alerts = []
        
        # Check sustained high bandwidth usage
        if upload_rate > self.alert_thresholds['bandwidth']:
            alerts.append({
                'type': 'bandwidth',
                'severity': 'warning',
                'message': f'High upload rate: {self.format_bytes(upload_rate)}/s',
                'threshold': self.format_bytes(self.alert_thresholds['bandwidth']) + '/s'
            })
        
        if download_rate > self.alert_thresholds['bandwidth']:
            alerts.append({
                'type': 'bandwidth',
                'severity': 'warning',
                'message': f'High download rate: {self.format_bytes(download_rate)}/s',
                'threshold': self.format_bytes(self.alert_thresholds['bandwidth']) + '/s'
            })
        
        # Calculate percentage of threshold
        upload_percent = (upload_rate / self.alert_thresholds['bandwidth']) * 100
        download_percent = (download_rate / self.alert_thresholds['bandwidth']) * 100
        
        # Add warnings at 80% of threshold
        if upload_percent >= 80 and upload_percent < 100:
            alerts.append({
                'type': 'bandwidth',
                'severity': 'info',
                'message': f'Upload rate at {upload_percent:.1f}% of threshold',
                'threshold': self.format_bytes(self.alert_thresholds['bandwidth']) + '/s'
            })
        
        if download_percent >= 80 and download_percent < 100:
            alerts.append({
                'type': 'bandwidth',
                'severity': 'info',
                'message': f'Download rate at {download_percent:.1f}% of threshold',
                'threshold': self.format_bytes(self.alert_thresholds['bandwidth']) + '/s'
            })
        
        return alerts

    def get_peer_alerts(self, peer):
        """Check for peer-related alerts."""
        alerts = []
        
        # Check latency
        if peer['latency'] != 'N/A':
            latency = float(peer['latency'].rstrip('ms'))
            if latency > self.alert_thresholds['latency']:
                alerts.append({
                    'type': 'latency',
                    'severity': 'warning',
                    'message': f'High latency to {peer["name"]}: {latency}ms',
                    'threshold': f'{self.alert_thresholds["latency"]}ms'
                })
        
        # Add more peer-specific alerts here
        return alerts

    def check_system_alerts(self, resources):
        """Check for system resource alerts."""
        alerts = []
        
        # CPU Usage alerts
        if resources['cpu_percent'] > self.alert_thresholds['cpu']:
            alerts.append({
                'type': 'cpu',
                'severity': 'warning',
                'message': f'High CPU usage: {resources["cpu_percent"]}%',
                'threshold': f'{self.alert_thresholds["cpu"]}%'
            })
        elif resources['cpu_percent'] >= self.alert_thresholds['cpu'] * 0.8:
            alerts.append({
                'type': 'cpu',
                'severity': 'info',
                'message': f'CPU usage nearing threshold: {resources["cpu_percent"]}%',
                'threshold': f'{self.alert_thresholds["cpu"]}%'
            })
        
        # Memory Usage alerts
        if resources['memory_percent'] > self.alert_thresholds['memory']:
            alerts.append({
                'type': 'memory',
                'severity': 'warning',
                'message': f'High memory usage: {resources["memory_percent"]}%',
                'threshold': f'{self.alert_thresholds["memory"]}%'
            })
        elif resources['memory_percent'] >= self.alert_thresholds['memory'] * 0.8:
            alerts.append({
                'type': 'memory',
                'severity': 'info',
                'message': f'Memory usage nearing threshold: {resources["memory_percent"]}%',
                'threshold': f'{self.alert_thresholds["memory"]}%'
            })
        
        return alerts

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/stats')
def stats():
    if monitor:
        data = monitor.get_current_data()
        if data:
            return jsonify(data)
    return jsonify({'error': 'No data available'})

@app.route('/performance_test/<peer_ip>')
def performance_test(peer_ip):
    """Run performance tests for a specific peer."""
    if monitor:
        report = monitor.get_peer_performance_report(peer_ip)
        if report:
            return jsonify(report)
    return jsonify({'error': 'Could not run performance test'})

@app.route('/set_threshold/<metric>', methods=['POST'])
def set_threshold(metric):
    """Set an alert threshold."""
    if not monitor:
        return jsonify({'error': 'Monitor not initialized'})
    
    try:
        data = request.get_json()
        if 'value' not in data:
            return jsonify({'error': 'No value provided'})
        
        value = float(data['value'])
        if monitor.set_alert_threshold(metric, value):
            return jsonify({'success': True, 'message': f'Updated {metric} threshold to {value}'})
        else:
            return jsonify({'error': f'Invalid metric: {metric}'})
    except ValueError:
        return jsonify({'error': 'Invalid value provided'})
    except Exception as e:
        return jsonify({'error': str(e)})

if __name__ == "__main__":
    monitor = TailscaleMonitor()
    app.run(host='0.0.0.0', port=5000, debug=True) 