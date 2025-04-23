"""
Provides tools for analyzing domain-related information,
using only publicly accessible and legal data.
Sensitive or potentially risky data is automatically censored.
"""

import socket
import ssl
import requests
import dns.resolver
import whois
from ipwhois import IPWhois
from app.utils.logger import log, LogType


class Domain:
    """
    Initializes the domain object by cleaning the input (removing prefixes) 
    and resolving the domain name to its IP address for further analysis.
    """
    def __init__(self, domain: str):
        prefixes = ("https://", "http://", "www.")
        for prefix in prefixes:
            if domain.startswith(prefix):
                domain = domain[len(prefix):]
        self.domain = domain
        try:
            self._ip = socket.gethostbyname(self.domain)
            log(LogType.INFO, f"(Domain) IP resolved to {self._ip}")
        except socket.gaierror as error:
            log(LogType.ERROR, f"Couldn't resolve IP (Err) {error}")
            self._ip = None

    def headers(self) -> list:
        """ 
        Retrieves HTTP response headers from the website and 
        censors sensitive fields.
        """
        try:
            response = requests.get(f"https://{self.domain}", timeout=5)
            log(LogType.INFO, f"(Domain) Received headers for {self.domain}")
            headers = response.headers.items()
            prefix = "[CENSORED] Potential Exploits 🚨 "
            sensitive_keys = {
                "set-cookie": f"{prefix} session hijacking, unauthorized access",
                "authorization": f"{prefix} unauthorized access",
                "proxy-authorization": f"{prefix} breach of network security",
                "cookie": f"{prefix} session fixation attacks",
                "x-powered-by": f"{prefix} targeted attacks",
                "etag": f"{prefix} vulnerabilities, privacy risk",
                "link": f"{prefix} session hijacking, unauthorized access"
            }
            censored_headers = []
            for key, value in headers:
                k = key.lower()
                if k in sensitive_keys:
                    item = f"{key}: {sensitive_keys[k]}"
                    censored_headers.append(item)
                else:
                    censored_headers.append(f"{key}: {value}")
            return censored_headers

        except requests.RequestException as error:
            log(LogType.ERROR, f"(Domain) {error}")
            return []

    def dns_records(self) -> list:
        """ 
        Fetches DNS records for the domain, including A, MX, and NS records. 
        Adds a censored placeholder for potential sensitive TXT records.
        """
        records = {
            "A": "Address Record",
            "MX": "Mail Exchange Record",
            "NS": "Name Server Record"
        }
        censored_records = []
        for key, value in records.items():
            try:
                results = dns.resolver.resolve(self.domain, key, raise_on_no_answer=False)
                log(LogType.INFO, f"(Domain) Received {key} for {self.domain} ")
                for result in results:
                    if result:
                        censored_records.append(f"{value}: {result.to_text()}")
            except dns.resolver.NoAnswer as error:
                log(LogType.ERROR, f"(Domain) DNS Resolver No Answer | {error}")
                return []
            except Exception as error:
                log(LogType.ERROR, f"(Domain) {error}")
                return []
        if censored_records:
            censored_records.append(
                "Text Record: " +
                "[CENSORED] Potential Exploits 🚨 " +
                "leaking internal data, backdoor communication, " +
                "misconfigured security policies"
            )
        return censored_records

    def domain_info(self) -> list:
        """
        Fetches public WHOIS info about the domain, like registrar details and status, 
        while censoring sensitive data for privacy.
        """
        try:
            response = whois.whois(self.domain)
            data = response.items()
            sensitive_keys = {
                "registrant_name",
                "status",
                "registrar_url"
            }
            domain_info = []
            for key, value in data:
                if key.lower() in sensitive_keys:
                    domain_info.append(f"{key}: [CENSORED] 🚨 Privacy risk")
                else:
                    domain_info.append(f"{key}: {value}")
            return domain_info
        except Exception as error:
            log(LogType.ERROR, f"(Domain) {error}")
            return []

    def reversed_dns(self) -> list:
        """
        Looks up the host name for the domain's IP address and lists any alternate names 
        (aliases) and related IP addresses.
        """
        try:
            response = socket.gethostbyaddr(self._ip)
            log(LogType.INFO, f"(Domain) Reversed dns for {self.domain}")
            reversed_dns = []
            aliases = f"Aliases: {' , '.join(response[1])}"
            ips = f"IPs: {' , '.join(response[2])}"
            reversed_dns.append(f"Host: {response[0]}")
            if response[1]:
                reversed_dns.append(aliases)
            if response[2]:
                reversed_dns.append(ips)
            return reversed_dns
        except socket.herror as error:
            log(LogType.ERROR, f"(Domain) Socket Error | {error}")
            return []

    def ip_info(self):
        """
        Fetches information about the domain's IP address, including who owns it
        what network it belongs to, and a brief description of that network.
        """
        try:
            target = IPWhois(self._ip)
            response = target.lookup_rdap()
            log(LogType.INFO, f"(Domain) IP info for {self.domain}")
            ip_info = []
            ip_info.append(f"ASN: {response.get("asn")}")
            ip_info.append(f"ASN Description: {response.get("asn_description")}")
            ip_info.append(f"Network: {response.get("network", {}).get("name")}")
            return ip_info
        except Exception as error:
            log(LogType.ERROR, f"(Domain) ip_info | {error}")
            return []

    def ssl_cert(self) -> list:
        """
        Retrieves SSL certificate details for the specified domain, 
        censoring the serial number for security.
        """
        context = ssl.create_default_context()
        try:
            with socket.create_connection((self.domain, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert_data = ssock.getpeercert()
            if not cert_data:
                return []
            log(LogType.INFO, f"(Domain) SSL Certificate for {self.domain}")
            ssl_cert = []
            prefix = "[CENSORED] Potential Exploits 🚨"
            sensitive_keys = {
                "serialNumber": f"{prefix} SSL certificate forgery risk"
            }
            for key, value in cert_data.items():
                sanitized = sensitive_keys.get(key, value)
                ssl_cert.append(f"{key}: {sanitized}")
            return ssl_cert
        except ssl.SSLError as ssl_error:
            log(LogType.ERROR, f"(Domain) SSL Error | {ssl_error}")
            return []
        except socket.error as socket_error:
            log(LogType.ERROR, f"(Domain) Socket Error | {socket_error}")
            return []
        except Exception as error:
            log(LogType.ERROR, f"(Domain) {error}")
            return []
