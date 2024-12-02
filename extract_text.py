import os
from flask import Flask, request, render_template, send_file
from fpdf import FPDF
import requests
import builtwith
import nmap
import ssl
from urllib.parse import urlparse
import sublist3r
import whois
import time
from ipwhois import IPWhois
import socket
from bs4 import BeautifulSoup
from datetime import datetime


app = Flask(__name__)
class PDF(FPDF):
    def header(self):
        self.image('logo.jpg', 5, 5, 20)
        self.set_font('helvetica', 'B', 20)
        self.set_text_color(25, 202, 25)
        self.cell(80)
        self.cell(30, 10, 'Automated Recon-Report', ln=1, align='R')
        self.ln(20)

    def footer(self):
        self.set_y(-15)
        self.set_text_color(190, 190, 190)
        self.set_font('helvetica', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}', align='C')


def get_server_info(url):
    try:
        response = requests.get(url)
        server = response.headers.get('Server')
        return server
    except requests.exceptions.RequestException as e:
        return f"Error: {e}"

def identify_cms_frameworks(url):
    return builtwith.parse(url)

def analyze_security_headers(url):
    response = requests.get(url)
    security_headers = {
        'Content-Security-Policy': response.headers.get('Content-Security-Policy'),
        'Strict-Transport-Security': response.headers.get('Strict-Transport-Security'),
        'X-Frame-Options': response.headers.get('X-Frame-Options'),
        'X-XSS-Protection': response.headers.get('X-XSS-Protection'),
        'X-Content-Type-Options': response.headers.get('X-Content-Type-Options'),
        'Referrer-Policy': response.headers.get('Referrer-Policy')
    }
    return {k: v for k, v in security_headers.items() if v is not None}

def get_geolocation_and_hosting_info(domain):
    ip = socket.gethostbyname(domain)
    obj = IPWhois(ip)
    results = obj.lookup_rdap()
    geolocation = {
        'IP': ip,
        'ASN': results['asn'],
        'Country': results['asn_country_code'],
        'Organization': results['asn_description']
    }
    return geolocation

def enumerate_subdomains(domain):
    subdomains = sublist3r.main(domain, 40, savefile=None, ports=None, silent=True, verbose=False, enable_bruteforce=False, engines=None)
    return subdomains

def measure_page_load_time(url):
    start_time = time.time()
    response = requests.get(url)
    load_time = time.time() - start_time
    return load_time

def analyze_html_content(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    
    inline_scripts = len(soup.find_all('script', {'src': False}))
    deprecated_tags = len(soup.find_all(['font', 'center', 'marquee']))

    content_analysis = {
        'Inline Scripts': inline_scripts,
        'Deprecated Tags': deprecated_tags
    }
    return content_analysis

def get_whois_info(domain):
    domain_info = whois.whois(domain)
    return domain_info

def scan_ports(host):
    nm = nmap.PortScanner()
    nm.scan(host, '22-80')
    port_info = []
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for port in lport:
                port_info.append({
                    'port': port,
                    'state': nm[host][proto][port]['state']
                })
    return port_info

def get_ssl_info(hostname):
    context = ssl.create_default_context()
    conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=hostname)
    conn.connect((hostname, 443))
    cert = conn.getpeercert()
    return cert

def create_pdf(results):
    output_dir = '/path/to/output/directory'  # Adjust this path
    os.makedirs(output_dir, exist_ok=True)
    
    pdf = PDF('P', 'mm', 'A4')
    # Add the cover page
    pdf.add_page()
    pdf.set_font('helvetica', 'B', 36)
    pdf.set_text_color(0, 0, 0)
    page_width = pdf.w - 10  # Page width minus margin
    page_height = pdf.h - 10  # Page height minus margin
    pdf.set_xy(page_width - 190, page_height - 140)
    pdf.cell(180, 20, "Reconnaissance Report", align='R', ln=True)

    # Add date and a note
    now = datetime.now()
    pdf.set_font('helvetica', 'B', 10)
    pdf.set_text_color(190, 190, 190)
    pdf.cell(180, 0, f'Report Date : {now.strftime("%Y-%m-%d %H:%M:%S")}', align='R', ln=True)
    pdf.cell(180, 10, 'This Report is Produced using an Automated tool.', align='R', ln=True)

    # Add a new page for the index
    pdf.add_page()

    # Set up the index page
    pdf.set_font('helvetica', 'B', 24)
    pdf.set_text_color(0, 0, 0)
    pdf.cell(0, 20, 'Index', ln=True, align='L')

    pdf.set_font('helvetica', '', 12)
    pdf.ln(10)  # Add some space

    # Example index items
    index_items = [
    ('1. About', 2),
    ('2. Server Information', 3),
    ('3. Technologies Used', 4),
    ('4. Port Information', 5),
    ('5. SSL Information', 6),
    ('6. Subdomain Information', 7),
    ('7. Security Headers', 8),
    ('8. Page Load Time', 9),
    ('9. Geo-Location and Hosting',10),
    ('10. Content Analysis', 11)
    ]

    # Add index items with page numbers aligned to the right
    for item, page_num in index_items:
        pdf.set_x(10)  # Reset X position for each line
        pdf.cell(0, 10, item, ln=0, align='L')
        pdf.cell(-30)  # Move the cursor to the right end of the page
        pdf.cell(30, 10, str(page_num), ln=True, align='R')

    # Add a title page
    pdf.add_page()
    pdf.set_font('helvetica', 'B', 20)
    pdf.cell(0, 10, 'Reconnaissance Report', ln=True, align='C')
    pdf.set_font('helvetica', '', 12)
    pdf.cell(0, 10, 'This report contains various analyses of the provided URL.', ln=True, align='C')
    pdf.set_font('helvetica', 'BU', 16)
    pdf.cell(0, 10, 'The tools used.', ln=True, align='C')
    pdf.set_font('helvetica', '', 12)
    pdf.cell(0, 10, 'IPWhois: For obtaining geolocation and hosting information.', ln=True, align='C')
    pdf.cell(0, 10, 'sublist3r: For enumerating subdomains.', ln=True, align='C')
    pdf.cell(0, 10, 'whois: For getting WHOIS information.', ln=True, align='C')
    pdf.cell(0, 10, 'nmap: For scanning ports.', ln=True, align='C')
    pdf.cell(0, 10, 'ssl: For getting SSL information.', ln=True, align='C')

    # Add a new page for each section of results
    for section, content in results.items():
        pdf.add_page()
        pdf.set_font('helvetica', 'B', 16)
        pdf.cell(0, 10, section, ln=True)
        pdf.ln(10)
        
        pdf.set_font('helvetica', '', 12)
        if isinstance(content, dict):
            for key, value in content.items():
                pdf.multi_cell(0, 10, f'{key}: {value}')
        elif isinstance(content, list):
            for item in content:
                pdf.multi_cell(0, 10, str(item))
        else:
            pdf.multi_cell(0, 10, str(content))
    
    # Save PDF
    pdf_path = os.path.join(output_dir, 'recon_report.pdf')
    pdf.output(pdf_path)
    
    return pdf_path

# Original functions and routes

@app.route('/', methods=['GET', 'POST'])
def web_recon():
    if request.method == 'POST':
        url = request.form['url']
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname

        # Call the functions
        server_info = get_server_info(url)
        cms_frameworks = identify_cms_frameworks(url)
        port_info = scan_ports(hostname)
        ssl_info = get_ssl_info(hostname)
        subdomains = enumerate_subdomains(hostname)
        whois_info = get_whois_info(hostname)
        security_headers = analyze_security_headers(url)
        load_time = measure_page_load_time(url)
        geolocation_info = get_geolocation_and_hosting_info(hostname)
        content_analysis = analyze_html_content(url)

        results = {
            'Server Info': server_info,
            'Technologies': cms_frameworks,
            'Port Info': port_info,
            'SSL Info': ssl_info,
            'Subdomains': subdomains,
            'WHOIS Info': whois_info,
            'Security Headers': security_headers,
            'Page Load Time': load_time,
            'Geolocation and Hosting': geolocation_info,
            'Content Analysis': content_analysis
        }

        # Create the PDF report
        pdf_path = create_pdf(results)

        return send_file(pdf_path, as_attachment=True)

    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)