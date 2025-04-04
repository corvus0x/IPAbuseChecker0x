# IP Abuse Checker 0x

This script allows you to analyze a list of IP addresses using the [AbuseIPDB](https://www.abuseipdb.com/) API. It generates reports in CSV and HTML formats and displays a detailed summary in the console with a well-formatted and color-highlighted table. It is particularly useful for handling security incidents when there are many IPs to investigate.

AbuseIPDB provides a free analysis of up to 1,000 IPs per day, allowing users to check multiple addresses without cost.

Additionally, the script groups IPs into three categories depending on their confidence score, which indicates how likely they are to be risky:

🔴 High Risk IPs (>40 confidence)

🟠 Medium Risk IPs (1-39 confidence)

🟢 Informational (0 confidence)


<p align="center">
<img src=https://imgur.com/q3W8as5.png">
</p>


## Features

- Queries multiple IP addresses in parallel for efficiency.
- Generates a visually structured **HTML report**  that makes it easy to analyze the investigated IPs.
- Creates a **CSV report** for running queries, importing into data programs, or generating tables.
- Displays a visual summary in the console with risk categories and TOR nodes.

## Requirements

Before running the script, install the required dependencies:

```bash
pip install requests csv tqdm tabulate colorama pycountry
```

## Usage

1. Insert your AbuseIPDB API key in the script before executing it.
2. Place the IP addresses to be analyzed in a file named `ips.txt` (one IP per line).
3. Run the script:

```bash
python IPAbuseChecker0x.py
```

4. After execution, the following files will be generated:
   - **`report_IPAbuseChecker0x.html`**: An HTML report with color-coded risk levels for easier interpretation.
   - **`results_IPAbuseChecker0x.csv`**: Contains detailed information about the analyzed IPs.
   - A structured **summary table** will be displayed in the console.

## Configuration

### API Key

The script uses the **AbuseIPDB** API, so you need an API key. Replace the `API_KEY` variable in the script with your own key:

```python
API_KEY = 'YOUR_API_KEY'
```

### Adjusting the Number of Threads (Optional)

The script uses concurrency to speed up the IP queries. You can modify the number of threads in this line:

```python
with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
```

Adjust `max_workers` according to your system's capability and the number of IPs to process.

## Example Output


### HTML:

A visual report is generated with color coding to indicate the risk level of each IP.

<p align="center">
<img src=https://imgur.com/5P1TCWG.png>
</p>


### CSV:

A structured CSV report is generated containing detailed information about each analyzed IP, including confidence scores, ISP details, domain, country, and whether the IP is associated with TOR nodes.

Note: The CSV file is generated in its traditional format, but the following image displays it as a table to better visualize all columns and data.

<p align="center">
<img src=https://imgur.com/XQCRxoc.png>
</p>


## Contributions

If you want to improve the script or add new features, feel free to contribute! Fork the repository and submit a **pull request**.

## License

This project is licensed under the MIT License. You are free to use and modify it as needed.