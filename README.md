# IP Abuse Checker 0x

This script allows you to analyze a list of IP addresses using the **AbuseIPDB** API. It generates reports in CSV and HTML formats and displays a detailed summary in the console with a well-formatted and color-highlighted table. It is particularly useful for **handling security incidents** when there are many IPs to investigate.

<p align="center">
<img width=1303 height=300 src=https://imgur.com/k8SFEcn.png">
</p>



## Features

- Queries multiple IP addresses in parallel for efficiency.
- Generates reports in **CSV** and **HTML** formats with detailed analysis.
- Displays a visual summary in the console with risk categories and TOR nodes.
- Uses **colorama**, **tabulate**, and **tqdm** for improved visualization and process tracking.

## Requirements

Before running the script, install the required dependencies:

```bash
pip install requests tqdm tabulate colorama
```

## Usage

1. Place the IP addresses to be analyzed in a file named `ips.txt` (one IP per line).
2. Run the script:

```bash
python IPAbuseChecker0x.py
```

3. After execution, the following files will be generated:
   - `resultsABIP.csv`: Contains detailed information about the analyzed IPs.
   - `report.html`: An HTML report with color-coded risk levels for easier interpretation.
   - A structured summary table will be displayed in the console.

## Configuration

### API Key

The script uses the **AbuseIPDB** API, so you need an API key. Replace the `API_KEY` variable in the script with your own key:

```python
API_KEY = 'YOUR_API_KEY'
```

### Adjusting the Number of Threads

The script uses concurrency to speed up the IP queries. You can modify the number of threads in this line:

```python
with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
```

Adjust `max_workers` according to your system's capability and the number of IPs to process.

## Example Output


### HTML:

A visual report is generated with color coding to indicate the risk level of each IP.

<p align="center">
<img width=1303 height=410 src=https://imgur.com/kAzGLMl.png>
</p>


### CSV:

A structured CSV report is generated containing detailed information about each analyzed IP, including confidence scores, ISP details, domain, country, and whether the IP is associated with TOR nodes.

## Contributions

If you want to improve the script or add new features, feel free to contribute! Fork the repository and submit a **pull request**.

## License

This project is licensed under the MIT License. You are free to use and modify it as needed.


