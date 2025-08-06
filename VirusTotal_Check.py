import requests
import time
import hashlib

#User input
x = int(input("1: URL or IP Check\n2: File Hash Check\nFor example for URL address and IP address: http://example.com or http://1.1.1.1\nPlease enter a number: "))

def load_api_key(path="api_key.txt"):
    try:
        with open(path, "r") as f:
            key = f.read().strip()
            if not key:
                raise ValueError("File is empty; please write your API Key inside the 'api_key.txt'.")
            return key
    except FileNotFoundError:
        raise FileNotFoundError(f"API key file not found in: {path}")
    except Exception as e:
        raise RuntimeError(f"API Key runtime error: {e}")

#Definitions
API_KEY = load_api_key()
scan_url_file = 'https://www.virustotal.com/vtapi/v2/file/scan'
report_url_file = 'https://www.virustotal.com/vtapi/v2/file/report'
scan_url_ip = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
scan_url_url = 'https://www.virustotal.com/vtapi/v2/url/report'
Block_size = 65536

def hash_checker(file_path):
    hasher = hashlib.sha256()
    with open(file_path, 'rb') as f:
        buf = f.read(Block_size)
        while len(buf) > 0:
            hasher.update(buf)
            buf = f.read(Block_size)
    #Return computed hash
    return hasher.hexdigest()

def check_file_reputation(file_hash):
    report_params = {
        'apikey': API_KEY,
        'resource': file_hash
    }

    try:
        report_response = requests.get(report_url_file, params=report_params)
        report_response.raise_for_status()

        report_result = report_response.json()
        if report_result.get('response_code') == 1:
            positives = report_result.get('positives', 0)
            total = report_result.get('total', 0)

            print(f"File Hash: {file_hash}")
            print(f"Total number of scans: {total}")
            print(f"Number of dangerous cases: {positives}")

            if positives > 0:
                print("\nWarning! File seems suspicious!")
                print("\nEngine(s) Response:\n")
                for vendor, result in report_result.get('scans', {}).items():
                    if result.get('detected'):
                        print(f"{vendor}: {result.get('result')}")
            else:
                print("""File seems safe""")

        return report_result

    except requests.exceptions.RequestException as re:
        print("HTTP error:", re)
    except Exception as e:
        print("General Error:", e)

def send_file_to_virustotal(file_path):
    with open(file_path, 'rb') as f:
        files = {'file': (file_path, f)}
        params = {'apikey': API_KEY}
        response = requests.post(scan_url_file, files=files, params=params)
        response.raise_for_status()
        return response.json()

def check_ip_reputation(ip_address):
    report_params = {
        'apikey': API_KEY,
        'ip': ip_address
    }

    try:
        report_response = requests.get(scan_url_ip, params=report_params)
        report_response.raise_for_status()

        report_result = report_response.json()
        if report_result.get('response_code') == 1:
            positives = report_result.get('positives', 0)
            total = report_result.get('total', 0)

            print(f"IP Address: {ip_address}")
            print(f"Total number of scans: {total}")
            print(f"Number of dangerous cases: {positives}")

            if positives > 0:
                print("\n""Warning! IP seems suspicious!""")
                print("\nEngine(s) Response:\n")
                for vendor, result in report_result.get('scans', {}).items():
                    if result.get('detected'):
                        print(f"{vendor}: {result.get('result')}")
            else:
                print("IP is safe for now")
        else:
            print("No report found for this IP address.")

        return report_result

    except requests.exceptions.RequestException as re:
        print("HTTP error:", re)
    except Exception as e:
        print("General Error:", e)

def check_url_reputation(url):
    report_params = {
        'apikey': API_KEY,
        'resource': url
    }

    try:
        report_response = requests.get(scan_url_url, params=report_params)
        report_response.raise_for_status()

        report_result = report_response.json()
        if report_result.get('response_code') == 1:
            positives = report_result.get('positives', 0)
            total = report_result.get('total', 0)

            print(f"URL: {url}")
            print(f"Total number of scans: {total}")
            print(f"Number of dangerous cases: {positives}")

            if positives > 0:
                print("\nWarning! URL seems suspicious!")
                print("\nEngine(s) Response:\n")
                for vendor, result in report_result.get('scans', {}).items():
                    if result.get('detected'):
                        print(f"{vendor}: {result.get('result')}")
            else:
                print("URL is safe for now")
        else:
            print("No report found for this URL.")

        return report_result

    except requests.exceptions.RequestException as re:
        print("HTTP error:", re)
    except Exception as e:
        print("General Error:", e)

if __name__ == "__main__":
    if x == 2:
        file_path = input("Please enter the location of the file: ").strip('"')
        
        #Compute hash
        file_hash = hash_checker(file_path)
        print(f"Computed SHA-256 hash: {file_hash}")

        #Send file to VirusTotal
        print("Sending file to VirusTotal for scanning...")
        send_file_response = send_file_to_virustotal(file_path)
        print("File sent to VirusTotal. Scan ID:", send_file_response.get('scan_id'))

        #Wait and check file 
        time.sleep(15)
        check_file_reputation(file_hash)
    
    elif x == 1:
        resource = input("Please enter the URL or IP address: ").strip()
        
        #heck if input IP or URL
        if resource.replace('.', '').isdigit() and len(resource.split('.')) == 4:
            #Check IP
            check_ip_reputation(resource)
        else:
            #Check URL
            check_url_reputation(resource)

    elif x < 1 or x > 2:
        print("Please enter a valid number!")