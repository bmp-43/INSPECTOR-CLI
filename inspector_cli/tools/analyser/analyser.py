import builtins
print = builtins.print
from colorama import Fore, Style
import requests
import datetime
import os
import base64
import time
import sys
import hashlib




# Base class for all analysis types — stores the VirusTotal API key
class MalwareAnalyser:
    def __init__(self, settings, api_key):
        self.api_key = api_key
        self.settings = settings


# Class for analyzing hash values — identifies hash type and queries VirusTotal
class HashScanner(MalwareAnalyser):
    def __init__(self, settings, api_key, h_value, fail = 0):
        super().__init__(settings, api_key)
        self.h_value = h_value
        self.fail = fail


    # Checks if the hash format matches bcrypt pattern (60 characters with $2a$, $2b$, $2y$)
    def bcrypt_check(self):
        if self.h_value.startswith(("$2a$", "$2b$", "$2y$")) and len(self.h_value) == 60:
            print(f"{Fore.BLUE}Provided hash is bcrypt{Style.RESET_ALL}", log=True)
        else:
            self.fail += 1


    # Checks if hash is likely MD5 or NTLM based on hex and casing
    def md5_ntlm_check(self):
        if len(self.h_value) == 32 and all(c in "0123456789abcdefABCDEF" for c in self.h_value):
            if self.h_value.isupper():
                print(f"{Fore.BLUE}Likely NTLM (uppercase hex){Style.RESET_ALL}", log=True)
            elif self.h_value.islower():
                print(f"{Fore.BLUE}Likely MD5 (lowercase hex){Style.RESET_ALL}", log=True)
            else:
                print(f"{Fore.BLUE}Could be either MD5 or NTLM — indistinguishable without context.{Style.RESET_ALL}", log=True)
        else:
            self.fail += 1


    # Detects SHA1, SHA256, SHA512 based on hash length and format for example SHA256 9335468d11de69ea17a68a304054fb2b4822442ca98d297d22da44e1d9b1e5e2
    def sha_check(self):
        if len(self.h_value) == 40 and all(c in "0123456789abcdefABCDEF" for c in self.h_value):
            print(f"{Fore.BLUE}The hash you provided is likely SHA1 (or possibly RIPEMD-160){Style.RESET_ALL}", log=True)
        elif len(self.h_value) == 64 and all(c in "0123456789abcdefABCDEF" for c in self.h_value):
            print(f"{Fore.BLUE}The hash you provided is likely SHA256 (possibly SHA3-256, indistinguishable without context){Style.RESET_ALL}", log=True)
        elif len(self.h_value) == 128 and all(c in "0123456789abcdefABCDEF" for c in self.h_value):
            print(f"{Fore.BLUE}The hash you provided is likely SHA512{Style.RESET_ALL}", log=True)
        else:
            self.fail += 1


    # Identifies MySQL 5.x password hashes (starts with '*' and 41 chars long)
    def mysql5_check(self):
        if len(self.h_value) == 41 and self.h_value.startswith("*"):
            body = self.h_value[1:]
            if all(c in "0123456789ABCDEF" for c in body):
                print(f"{Fore.BLUE}The hash you provided is likely MySQL 5.x{Style.RESET_ALL}", log=True)
            else:
                self.fail += 1
        else:
            self.fail += 1


    # Identifies simple 8-character CRC32 hashes
    def crc32_check(self):
        if len(self.h_value) == 8 and all(c in "0123456789abcdefABCDEF" for c in self.h_value):
            print(f"{Fore.BLUE}The hash you provided is likely CRC32 (non-cryptographic){Style.RESET_ALL}", log=True)
        else:
            self.fail += 1



    # Sends a VirusTotal API request to fetch full analysis report for a hash
    def vt_lookup(self, hash_value):
        if not self.api_key:
            print(f"{Fore.RED}[VT] API key not found. Please set it in config/keys.txt{Style.RESET_ALL}", log=True)
            return

        headers = {
            "x-apikey": self.api_key
        }
        url = f"https://www.virustotal.com/api/v3/files/{hash_value}"

        try:
            print(f"{Fore.LIGHTBLACK_EX}Querying VirusTotal...{Style.RESET_ALL}", log=True)
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                data = response.json()["data"]["attributes"]

                # Detection stats
                stats = data["last_analysis_stats"]
                total = sum(stats.values())
                malicious = stats.get("malicious", 0)

                # Submission date
                sub_date = data.get("first_submission_date")
                if sub_date:
                    sub_date = datetime.datetime.fromtimestamp(sub_date, datetime.UTC).strftime('%Y-%m-%d %H:%M:%S UTC')

                else:
                    sub_date = "Unknown"

                # Collect malware names
                engines = data.get("last_analysis_results", {})
                malware_labels = set()
                for engine in engines.values():
                    if engine["category"] == "malicious":
                        malware_labels.add(engine["result"])
                malware_labels = list(malware_labels)[:5]  # limit to top 5 unique labels

                # Print full report
                print(f"{Fore.YELLOW}\n[+] VT Detection: {malicious}/{total} engines flagged this file", log=True)
                print(f"[+] First Submission: {sub_date}", log=True)
                print(f"[+] Malware Labels:", log=True)
                if malware_labels:
                    for label in malware_labels:
                        print(f"    - {label}", log=True)
                else:
                    print("    - None provided by engines", log=True)
                print(f"[+] Report: https://www.virustotal.com/gui/file/{hash_value}{Style.RESET_ALL}\n", log=True)

            elif response.status_code == 404:
                print(f"{Fore.CYAN}[VT] Hash not found on VirusTotal.{Style.RESET_ALL}", log=True)
            else:
                print(f"{Fore.RED}[VT] Error {response.status_code}: {response.text}{Style.RESET_ALL}", log=True)

        except Exception as e:
            print(f"{Fore.RED}[VT] Exception: {e}{Style.RESET_ALL}", log=True)

    # Entry point for hash scanning: checks format, then fetches VT report if recognized
    def start(self):
        try:
            while True:
                
                if not self.h_value:
                    print(f"{Fore.RED}[!] Hash cannot be empty. Try again.{Style.RESET_ALL}", log=True)
                    continue
                self.fail = 0  
                self.bcrypt_check()
                self.md5_ntlm_check()
                self.sha_check()
                self.mysql5_check()
                self.crc32_check()
                if self.fail < 5:
                    self.vt_lookup(self.h_value)
                    break 
                else:
                    print(f"{Fore.RED}[!] Unrecognized hash. Please try again.{Style.RESET_ALL}", log=True)
        except KeyboardInterrupt:
            print(f"{Fore.YELLOW}[x] Scan cancelled by user.{Style.RESET_ALL}", log=True)
        except Exception as e:
            print(f"{Fore.RED}[!] An unexpected error occurred: {e}{Style.RESET_ALL}", log=True)



# Class for analyzing URLs with VirusTotal — checks reputation and detection history
class UrlAnalyser(MalwareAnalyser):
    def __init__(self, settings, api_key, url):
        super().__init__(settings, api_key)
        self.raw_url = url
        self.encoded_url = base64.urlsafe_b64encode(url.encode()).decode().strip("=")


    # Queries VirusTotal for URL analysis — falls back to submission if URL is unknown
    def vt_url_lookup(self):
        if not self.api_key:
            print(f"{Fore.RED}[VT] API key not found. Please set it in config/keys.txt{Style.RESET_ALL}", log=True)
            return

        headers = {
            "x-apikey": self.api_key
        }
        final_url = f"https://www.virustotal.com/api/v3/urls/{self.encoded_url}"

        try:
            response = requests.get(final_url, headers=headers)
            if response.status_code == 200:
                data = response.json()["data"]["attributes"]

                # Detection stats
                stats = data["last_analysis_stats"]
                total = sum(stats.values())
                malicious = stats.get("malicious", 0)

                # Submission date
                sub_date = data.get("first_submission_date")
                if sub_date:
                    sub_date = datetime.datetime.fromtimestamp(sub_date, datetime.UTC).strftime('%Y-%m-%d %H:%M:%S UTC')
                else:
                    sub_date = "Unknown"

                # Collect malware names
                engines = data.get("last_analysis_results", {})
                malware_labels = set()
                for engine in engines.values():
                    if engine["category"] == "malicious":
                        malware_labels.add(engine["result"])
                malware_labels = list(malware_labels)[:5]

                # Print full report
                print(f"{Fore.YELLOW}\n[+] VT Detection: {malicious}/{total} engines flagged this URL", log=True)
                print(f"[+] First Submission: {sub_date}", log=True)
                print(f"[+] Malware Labels:", log=True)
                if malware_labels:
                    for label in malware_labels:
                        print(f"    - {label}", log=True)
                else:
                    print("    - None provided by engines", log=True)
                print(f"[+] Report: https://www.virustotal.com/gui/url/{response.json()['data']['id']}{Style.RESET_ALL}\n", log=True)


            elif response.status_code == 404:
                print(f"{Fore.CYAN}[VT] URL not found. Submitting now...{Style.RESET_ALL}", log=True)
                self.vt_url_submit()
            else:
                print(f"{Fore.RED}[VT] Error {response.status_code}: {response.text}{Style.RESET_ALL}", log=True)

        except Exception as e:
            print(f"{Fore.RED}[VT] Lookup error: {e}{Style.RESET_ALL}", log=True)


    # Submits a new URL to VirusTotal for analysis when it hasn't been seen before
    def vt_url_submit(self):
        headers = {
            "x-apikey": self.api_key,
            "Content-Type": "application/x-www-form-urlencoded"
        }
        url = "https://www.virustotal.com/api/v3/urls"

        try:
            response = requests.post(url, headers=headers, data=f"url={self.raw_url}")
            if response.status_code == 200:
                data = response.json()["data"]
                print(f"{Fore.GREEN}[+] URL submitted for scanning.", log=True)
                print(f"[+] GUI link: https://www.virustotal.com/gui/url/{data['id']}{Style.RESET_ALL}", log=True)
            else:
                print(f"{Fore.RED}[VT] Submission failed: {response.status_code} — {response.text}{Style.RESET_ALL}", log=True)
        except Exception as e:
            print(f"{Fore.RED}[VT] URL submit error: {e}{Style.RESET_ALL}", log=True)



# Class for analyzing file uploads via VirusTotal API
class FileAnalyser(MalwareAnalyser):
    def __init__(self, settings, api_key, file_path):
        super().__init__(settings, api_key)
        self.file_path = file_path


    # Uploads the file to VirusTotal and waits for it to be analyzed
    def vt_file_scan(self):
        if not self.api_key:
            print(f"{Fore.RED}[VT] API key not found. Please set it in config/keys.txt{Style.RESET_ALL}", log=True)
            return

        if not os.path.isfile(self.file_path):
            print(f"{Fore.RED}[!] File not found: {self.file_path}{Style.RESET_ALL}", log=True)
            return

        headers = {"x-apikey": self.api_key}

        try:
            with open(self.file_path, "rb") as f:
                files = {"file": (os.path.basename(self.file_path), f)}
                print(f"{Fore.LIGHTBLACK_EX}Uploading file to VirusTotal...{Style.RESET_ALL}", log=True)
                response = requests.post("https://www.virustotal.com/api/v3/files", headers=headers, files=files)

            if response.status_code == 200:
                upload_data = response.json()["data"]
                analysis_id = upload_data["id"]
                file_sha256 = self.calculate_sha256()  # fallback if available
                print(f"{Fore.GREEN}[+] File uploaded. Waiting for analysis...{Style.RESET_ALL}", log=True)
                self.wait_for_report(analysis_id, headers, fallback_sha=file_sha256)

            elif response.status_code == 409:
                file_id = response.json()["error"]["message"].split()[-1]
                print(f"{Fore.YELLOW}[VT] File already exists. Fetching report...{Style.RESET_ALL}", log=True)
                self.fetch_final_file_report(file_id, headers)

            else:
                print(f"{Fore.RED}[VT] Submission failed: {response.status_code} — {response.text}{Style.RESET_ALL}", log=True)
        except Exception as e:
            print(f"{Fore.RED}[VT] File scan error: {e}{Style.RESET_ALL}", log=True)


    # Polls the VT analysis endpoint until the file analysis is complete
    def wait_for_report(self, analysis_id, headers, fallback_sha=None):
        try:
            while True:
                time.sleep(10)
                url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
                response = requests.get(url, headers=headers)

                if response.status_code == 200:
                    data = response.json().get("data", {})
                    status = data.get("attributes", {}).get("status")

                    if status != "completed":
                        print(f"{Fore.LIGHTBLACK_EX}[!] Analysis in progress... waiting...{Style.RESET_ALL}", log=True)
                        continue
                    else:
                        # Try to get SHA256 from meta
                        file_sha = data.get("meta", {}).get("file_info", {}).get("sha256") or fallback_sha
                        if not file_sha:
                            print(f"{Fore.RED}[!] Couldn't determine file SHA256 to fetch full report.{Style.RESET_ALL}", log=True)
                            return
                        self.fetch_final_file_report(file_sha, headers)
                        break

                else:
                    print(f"{Fore.RED}[!] Error fetching analysis status: {response.status_code} — {response.text}{Style.RESET_ALL}", log=True)
        except KeyboardInterrupt:
            print(f"{Fore.YELLOW}[x] Scan interrupted by user.{Style.RESET_ALL}", log=True)


    # Retrieves the final detailed report for a scanned file
    def fetch_final_file_report(self, file_id, headers):
        url = f"https://www.virustotal.com/api/v3/files/{file_id}"
        response = requests.get(url, headers=headers)
        if response.status_code != 200:
            print(f"{Fore.RED}[!] Error fetching final report: {response.status_code}{Style.RESET_ALL}", log=True)
            return

        attributes = response.json()["data"]["attributes"]
        stats = attributes["last_analysis_stats"]
        total = sum(stats.values())
        malicious = stats.get("malicious", 0)

        sub_date = attributes.get("first_submission_date")
        if sub_date:
            sub_date = datetime.datetime.fromtimestamp(sub_date, datetime.UTC).strftime('%Y-%m-%d %H:%M:%S UTC')
        else:
            sub_date = "Unknown"

        engines = attributes["last_analysis_results"]
        malware_labels = set()
        for engine in engines.values():
            if engine["category"] == "malicious" and engine["result"]:
                malware_labels.add(engine["result"])
        malware_labels = list(malware_labels)[:5]

        print(f"{Fore.YELLOW}\n[+] VT Detection: {malicious}/{total} engines flagged this file", log=True)
        print(f"[+] First Submission: {sub_date}", log=True)
        print(f"[+] Malware Labels:", log=True)
        if malware_labels:
            for label in malware_labels:
                print(f"    - {label}", log=True)
        else:
            print("    - None provided by engines", log=True)
        print(f"[+] Report: https://www.virustotal.com/gui/file/{file_id}{Style.RESET_ALL}\n", log=True)



    # Computes SHA256 hash of a local file — used for matching reports
    def calculate_sha256(self):
        sha256 = hashlib.sha256()
        with open(self.file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()




# Validates the VirusTotal API key by pinging the user info endpoint
def check_vt_key_valid(api_key):
    headers = {"x-apikey": api_key}
    try:
        response = requests.get("https://www.virustotal.com/api/v3/users/me", headers=headers)
        return response.status_code == 200
    except:
        return False



# Main entry point for choosing hash, URL, or file analysis from user input
def main(settings):
    try:
        if not check_vt_key_valid(api_key=settings["malware_analyser"]["vt_api_key"]):
            print(f"{Fore.RED}[!] Invalid VirusTotal API key. Please check your settings{Style.RESET_ALL}", log=True)
            sys.exit()
    except Exception as e:
        print(f"{Fore.RED}[!] Unexpected error occurred. - {e}{Style.RESET_ALL}", log=True)


    try:
        mode = input("Pick What are you gonna Analyse: \n 1. Hash \n 2. URL \n 3. File \n")
        if mode == "1" or mode.lower() == "hash":
            hash_instance = HashScanner(api_key=settings["malware_analyser"]["vt_api_key"], h_value=input("Provide hash for scanning: ").strip())
            hash_instance.start()
        elif mode == "2" or mode.lower() == "url":
            url_instance = UrlAnalyser(api_key=settings["malware_analyser"]["vt_api_key"], url=input("Provide URL for scanning: ").strip())
            url_instance.vt_url_lookup()
        elif mode == "3" or mode.lower() == "file":
            file_instance = FileAnalyser(api_key=settings["malware_analyser"]["vt_api_key"], file_path=input("Enter path to file: ").strip())
            file_instance.vt_file_scan()

    except KeyboardInterrupt:
        print(f"{Fore.YELLOW}[x] Interrupted by user. Shutting down...{Style.RESET_ALL}", log=True)
    except Exception as e:
        print(f"{Fore.RED}[!] Unexpected error occurred. - {e}{Style.RESET_ALL}", log=True)
