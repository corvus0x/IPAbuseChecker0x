import requests
import csv
import concurrent.futures
from tqdm import tqdm
from tabulate import tabulate
from colorama import Fore, Style
import pycountry
import sys
from datetime import datetime

# Define the AbuseIPDB API key
API_KEY = 'YOUR_API_KEY'

# Check if API_KEY is set
if API_KEY == "YOUR_API_KEY":
    print(f"{Fore.RED}Error: Please insert your AbuseIPDB API Key in the API_KEY variable.{Style.RESET_ALL}")
    sys.exit(1)

# Base API URL
API_URL = 'https://api.abuseipdb.com/api/v2/check'

# Application logo
def print_logo():
    logo = r"""
    ________     ___    __                       ________              __                ____      
   /  _/ __ \   /   |  / /_  __  __________     / ____/ /_  ___  _____/ /_____  _____   / __ \_  __
   / // /_/ /  / /| | / __ \/ / / / ___/ _ \   / /   / __ \/ _ \/ ___/ //_/ _ \/ ___/  / / / / |/_/
 _/ // ____/  / ___ |/ /_/ / /_/ (__  )  __/  / /___/ / / /  __/ /__/ ,< /  __/ /     / /_/ />  <  
/___/_/      /_/  |_/_.___/\__,_/____/\___/   \____/_/ /_/\___/\___/_/|_|\___/_/      \____/_/|_|                                                                                                                                                                                                                                                            
    by corvus0x
    """
    print(Fore.CYAN + logo + Style.RESET_ALL)

# Function to fetch IP information from AbuseIPDB API
def get_ip_info(ip):
    headers = {
        'Key': API_KEY,
        'Accept': 'application/json'
    }
    params = {
        'ipAddress': ip,
        'maxAgeInDays': '360'
    }
    try:
        response = requests.get(API_URL, headers=headers, params=params)

        if response.status_code == 200:
            return response.json()['data']
        else:
            print(f"Error fetching information for IP {ip}: {response.status_code}")
            return None
    except Exception as e:
        print(f"Error processing IP {ip}: {e}")
        return None

# Function to process an IP and return the required data
def process_ip(ip):
    ip_info = get_ip_info(ip)
    if ip_info:
        country_name = pycountry.countries.get(alpha_2=ip_info['countryCode']).name if ip_info['countryCode'] else 'Unknown'
        last_reported = ip_info['lastReportedAt']
        formatted_date = datetime.strptime(last_reported, "%Y-%m-%dT%H:%M:%S%z").strftime("%d-%b-%Y %H:%M UTC") if last_reported else 'No reports'
        return [
            ip_info['ipAddress'],
            ip_info['abuseConfidenceScore'],
            ip_info['isp'],
            ip_info['domain'],
            country_name,
            ip_info['totalReports'],
            ip_info.get('isWhitelisted', 'N/A'),
            ip_info.get('isTor', 'N/A'),
            formatted_date
        ]
    return None

# Function to generate an HTML report
def generate_html_report(results, summary, output_html):
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>IPAbuseChecker0x Report</title>
        <style>
            body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background-color: #f4f4f9; color: #333; }}
            h1 {{
                color: #444;
                text-align: center;
                margin-top: 20px;
                font-size: 48px;
                font-weight: 900;
            }}
            h1::after {{
                content: '';
                display: block;
                width: 50px;
                margin: 10px auto;
                border-bottom: 3px solid #444;
            }}
            h2 {{ color: #333; margin-top: 30px; font-size: 24px; padding: 10px; }}
            .info-section, .tor-section, .non-tor-section {{
                width: 90%;
                margin: 30px auto;
                padding: 20px;
                border-radius: 8px;
                box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
                background-color: white;
            }}
            .info-section {{
                background-color: #f8f9fa;
                border-left: 5px solid #007bff;
            }}
            .tor-section {{
                border-left: 5px solid #dc3545;
            }}
            .non-tor-section {{
                border-left: 5px solid #28a745;
            }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 20px; box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1); }}
            th, td {{ border: 1px solid #ddd; padding: 12px; text-align: center; }}
            th {{ background-color: #000; color: #fff; font-size: 18px; }}
            td {{ font-size: 16px; color: #444; }}
            .high-risk {{ background-color: #ffdddd; color: black; }}
            .medium-risk {{ background-color: #fff5cc; color: black; }}
            .low-risk {{ background-color: #ddffdd; color: black; }}
            .tor {{ font-weight: bold; }}
            .highlight {{ background-color: #ffff99; }}
        </style>
    </head>
    <body>
        <h1>IPAbuseChecker0x Report</h1>

        <div class="info-section">
            <h2>Report Overview</h2>
            <p><strong>Total IPs Analyzed:</strong> {summary['total']}</p>
            <p><strong>🔴 High Risk IPs (>40 confidence):</strong> {summary['high_risk']}</p>
            <p><strong>🟠 Medium Risk IPs (1-39 confidence):</strong> {summary['medium_risk']}</p>
            <p><strong>🟢 Informational (0 confidence):</strong> {summary['low_risk']}</p>
            {"<p class='highlight'><strong>TOR Nodes:</strong> " + str(summary['tor']) + "</p>" if summary['tor'] > 0 else "<p><strong>TOR Nodes:</strong> " + str(summary['tor']) + "</p>"}
        </div>

        <table>
            <tr>
                <th>IP Address</th>
                <th>Abuse Confidence</th>
                <th>ISP</th>
                <th>Domain</th>
                <th>Country</th>
                <th>Total Reports</th>
                <th>Is Whitelisted</th>
                <th>Is TOR</th>
                <th>Last Reported</th>
            </tr>
    """

    # Sort results to have TOR nodes first, then by Abuse Confidence in descending order
    results.sort(key=lambda x: (not x[7], -x[1]))

    for row in results:
        risk_class = "high-risk" if row[1] > 40 else "medium-risk" if row[1] > 0 else "low-risk"
        tor_status = "✅" if row[7] == True else "❌"
        html_content += f"""
        <tr class="{risk_class}">
            <td>{row[0]}</td>
            <td>{row[1]}</td>
            <td>{row[2]}</td>
            <td>{row[3]}</td>
            <td>{row[4]}</td>
            <td>{row[5]}</td>
            <td>{row[6]}</td>
            <td class="tor">{tor_status}</td>
            <td>{row[8]}</td>
        </tr>
        """
    
    html_content += """</table></body></html>"""

    with open(output_html, "w", encoding="utf-8") as f:
        f.write(html_content)

# Function to read IPs from a file and process them in parallel
def process_ips(input_file, output_csv, output_html):
    print_logo()
    
    with open(input_file, 'r') as f:
        ips = [line.strip() for line in f.readlines()]

    results = []
    summary = {"total": len(ips), "high_risk": 0, "medium_risk": 0, "low_risk": 0, "tor": 0}

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        for result in tqdm(executor.map(process_ip, ips), total=len(ips), desc="Processing IPs"):
            if result:
                results.append(result)
                if result[1] > 40:
                    summary["high_risk"] += 1
                elif result[1] > 0:
                    summary["medium_risk"] += 1
                else:
                    summary["low_risk"] += 1
                if result[7] == True:
                    summary["tor"] += 1

    with open(output_csv, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["IP", "Confidence", "ISP", "Domain", "Country", "Reports", "Whitelisted", "TOR", "Last Report"])
        writer.writerows(results)
    
    generate_html_report(results, summary, output_html)

    # Display the classification summary in console
    classification_summary = [
        (f"{Fore.RED}TOP Critical (>40 confidence){Style.RESET_ALL}", summary["high_risk"], f"{Fore.YELLOW}{summary['tor']}{Style.RESET_ALL}" if summary["high_risk"] > 0 else "-"),
        (f"{Fore.YELLOW}TOP Medium (1-39 confidence){Style.RESET_ALL}", summary["medium_risk"], "-"),
        (f"{Fore.GREEN}Informational (0 confidence){Style.RESET_ALL}", summary["low_risk"], "-")
    ]
    
    print("\nIP Classification Summary:")
    print(tabulate(classification_summary, headers=["Category", "Number of IPs", "TOR Nodes"], tablefmt="fancy_grid"))
    print(f"\nTotal analyzed IPs: {summary['total']}")

    # Final message
    print(f"\n{Fore.GREEN}Report saved in {Fore.LIGHTYELLOW_EX}{output_html}{Fore.GREEN} and Data saved in {Fore.LIGHTYELLOW_EX}{output_csv}{Style.RESET_ALL}")

# Execute processing
process_ips('ips.txt', 'results_IPAbuseChecker0x.csv', 'report_IPAbuseChecker0x.html')