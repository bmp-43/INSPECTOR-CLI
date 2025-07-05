from colorama import Fore, Style
import requests
import datetime
import os
import base64
import time
import sys
import hashlib



def config(filename):
    config = {}
    with open(filename, "r") as f:
        for line in f:
            if "=" in line:
                key, value = line.strip().split("=", 1)
                config[key] = value
    return config

base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
config_path = os.path.join(base_dir, "config", "config.txt")
settings = config(config_path)


class MalwareAnalyser:
    def __init__(self, api_key):
        self.api_key = api_key

class HashScanner(MalwareAnalyser):
    def __init__(self, api_key, h_value, fail = 0):
        super().__init__(api_key)
        self.h_value = h_value
        self.fail = fail

    def bcrypt_check(self):
        if self.h_value.startswith(("$2a$", "$2b$", "$2y$")) and len(self.h_value) == 60:
            print(f"{Fore.BLUE}Provided hash is bcrypt{Style.RESET_ALL}")
        else:
            self.fail += 1

    def md5_ntlm_check(self):
        if len(self.h_value) == 32 and all(c in "0123456789abcdefABCDEF" for c in self.h_value):
            if self.h_value.isupper():
                print(f"{Fore.BLUE}Likely NTLM (uppercase hex){Style.RESET_ALL}")
            elif self.h_value.islower():
                print(f"{Fore.BLUE}Likely MD5 (lowercase hex){Style.RESET_ALL}")
            else:
                print(f"{Fore.BLUE}Could be either MD5 or NTLM — indistinguishable without context.{Style.RESET_ALL}")
        else:
            self.fail += 1

    def sha_check(self):
        if len(self.h_value) == 40 and all(c in "0123456789abcdefABCDEF" for c in self.h_value):
            print(f"{Fore.BLUE}The hash you provided is likely SHA1 (or possibly RIPEMD-160){Style.RESET_ALL}")
        elif len(self.h_value) == 64 and all(c in "0123456789abcdefABCDEF" for c in self.h_value):
            print(f"{Fore.BLUE}The hash you provided is likely SHA256 (possibly SHA3-256, indistinguishable without context){Style.RESET_ALL}")
        elif len(self.h_value) == 128 and all(c in "0123456789abcdefABCDEF" for c in self.h_value):
            print(f"{Fore.BLUE}The hash you provided is likely SHA512{Style.RESET_ALL}")
        else:
            self.fail += 1

    def mysql5_check(self):
        if len(self.h_value) == 41 and self.h_value.startswith("*"):
            body = self.h_value[1:]
            if all(c in "0123456789ABCDEF" for c in body):
                print(f"{Fore.BLUE}The hash you provided is likely MySQL 5.x{Style.RESET_ALL}")
            else:
                self.fail += 1
        else:
            self.fail += 1

    def crc32_check(self):
        if len(self.h_value) == 8 and all(c in "0123456789abcdefABCDEF" for c in self.h_value):
            print(f"{Fore.BLUE}The hash you provided is likely CRC32 (non-cryptographic){Style.RESET_ALL}")
        else:
            self.fail += 1



    def vt_lookup(self, hash_value):
        if not self.api_key:
            print(f"{Fore.RED}[VT] API key not found. Please set it in config/keys.txt{Style.RESET_ALL}")
            return

        headers = {
            "x-apikey": self.api_key
        }
        url = f"https://www.virustotal.com/api/v3/files/{hash_value}"

        try:
            print(f"{Fore.LIGHTBLACK_EX}Querying VirusTotal...{Style.RESET_ALL}")
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
                print(f"{Fore.YELLOW}\n[+] VT Detection: {malicious}/{total} engines flagged this file")
                print(f"[+] First Submission: {sub_date}")
                print(f"[+] Malware Labels:")
                if malware_labels:
                    for label in malware_labels:
                        print(f"    - {label}")
                else:
                    print("    - None provided by engines")
                print(f"[+] Report: https://www.virustotal.com/gui/file/{hash_value}{Style.RESET_ALL}\n")

            elif response.status_code == 404:
                print(f"{Fore.CYAN}[VT] Hash not found on VirusTotal.{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[VT] Error {response.status_code}: {response.text}{Style.RESET_ALL}")

        except Exception as e:
            print(f"{Fore.RED}[VT] Exception: {e}{Style.RESET_ALL}")
    def start(self):
        try:
            while True:
                
                if not self.h_value:
                    print(f"{Fore.RED}Hash cannot be empty. Try again.{Style.RESET_ALL}")
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
                    print(f"{Fore.RED}Unrecognized hash. Please try again.{Style.RESET_ALL}")
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}Scan cancelled by user.{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}An unexpected error occurred: {e}{Style.RESET_ALL}")


class UrlAnalyser(MalwareAnalyser):
    def __init__(self, api_key, url):
        super().__init__(api_key)
        self.raw_url = url
        self.encoded_url = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    def vt_url_lookup(self):
        if not self.api_key:
            print(f"{Fore.RED}[VT] API key not found. Please set it in config/keys.txt{Style.RESET_ALL}")
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
                print(f"{Fore.YELLOW}\n[+] VT Detection: {malicious}/{total} engines flagged this URL")
                print(f"[+] First Submission: {sub_date}")
                print(f"[+] Malware Labels:")
                if malware_labels:
                    for label in malware_labels:
                        print(f"    - {label}")
                else:
                    print("    - None provided by engines")
                print(f"[+] Report: https://www.virustotal.com/gui/url/{response.json()['data']['id']}{Style.RESET_ALL}\n")


            elif response.status_code == 404:
                print(f"{Fore.CYAN}[VT] URL not found. Submitting now...{Style.RESET_ALL}")
                self.vt_url_submit()
            else:
                print(f"{Fore.RED}[VT] Error {response.status_code}: {response.text}{Style.RESET_ALL}")

        except Exception as e:
            print(f"{Fore.RED}[VT] Lookup error: {e}{Style.RESET_ALL}")

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
                print(f"{Fore.GREEN}[+] URL submitted for scanning.")
                print(f"[+] GUI link: https://www.virustotal.com/gui/url/{data['id']}{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[VT] Submission failed: {response.status_code} — {response.text}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[VT] URL submit error: {e}{Style.RESET_ALL}")


class FileAnalyser(MalwareAnalyser):
    def __init__(self, api_key, file_path):
        super().__init__(api_key)
        self.file_path = file_path

    def vt_file_scan(self):
        if not self.api_key:
            print(f"{Fore.RED}[VT] API key not found. Please set it in config/keys.txt{Style.RESET_ALL}")
            return

        if not os.path.isfile(self.file_path):
            print(f"{Fore.RED}[!] File not found: {self.file_path}{Style.RESET_ALL}")
            return

        headers = {"x-apikey": self.api_key}

        try:
            with open(self.file_path, "rb") as f:
                files = {"file": (os.path.basename(self.file_path), f)}
                print(f"{Fore.LIGHTBLACK_EX}Uploading file to VirusTotal...{Style.RESET_ALL}")
                response = requests.post("https://www.virustotal.com/api/v3/files", headers=headers, files=files)

            if response.status_code == 200:
                upload_data = response.json()["data"]
                analysis_id = upload_data["id"]
                file_sha256 = self.calculate_sha256()  # fallback if available
                print(f"{Fore.GREEN}[+] File uploaded. Waiting for analysis...{Style.RESET_ALL}")
                self.wait_for_report(analysis_id, headers, fallback_sha=file_sha256)

            elif response.status_code == 409:
                file_id = response.json()["error"]["message"].split()[-1]
                print(f"{Fore.YELLOW}[VT] File already exists. Fetching report...{Style.RESET_ALL}")
                self.fetch_final_file_report(file_id, headers)

            else:
                print(f"{Fore.RED}[VT] Submission failed: {response.status_code} — {response.text}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[VT] File scan error: {e}{Style.RESET_ALL}")

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
                        print(f"{Fore.LIGHTBLACK_EX}[!] Analysis in progress... waiting...{Style.RESET_ALL}")
                        continue
                    else:
                        # Try to get SHA256 from meta
                        file_sha = data.get("meta", {}).get("file_info", {}).get("sha256") or fallback_sha
                        if not file_sha:
                            print(f"{Fore.RED}[!] Couldn't determine file SHA256 to fetch full report.{Style.RESET_ALL}")
                            return
                        self.fetch_final_file_report(file_sha, headers)
                        break

                else:
                    print(f"{Fore.RED}[!] Error fetching analysis status: {response.status_code} — {response.text}{Style.RESET_ALL}")
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}Scan interrupted by user.{Style.RESET_ALL}")

    def fetch_final_file_report(self, file_id, headers):
        url = f"https://www.virustotal.com/api/v3/files/{file_id}"
        response = requests.get(url, headers=headers)
        if response.status_code != 200:
            print(f"{Fore.RED}[!] Error fetching final report: {response.status_code}{Style.RESET_ALL}")
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

        print(f"{Fore.YELLOW}\n[+] VT Detection: {malicious}/{total} engines flagged this file")
        print(f"[+] First Submission: {sub_date}")
        print(f"[+] Malware Labels:")
        if malware_labels:
            for label in malware_labels:
                print(f"    - {label}")
        else:
            print("    - None provided by engines")
        print(f"[+] Report: https://www.virustotal.com/gui/file/{file_id}{Style.RESET_ALL}\n")


    def calculate_sha256(self):
        sha256 = hashlib.sha256()
        with open(self.file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()



def check_vt_key_valid(api_key):
    headers = {"x-apikey": api_key}
    try:
        response = requests.get("https://www.virustotal.com/api/v3/users/me", headers=headers)
        return response.status_code == 200
    except:
        return False


def main():
    try:
        if not check_vt_key_valid(api_key=settings.get("VT_api_key", None)):
            print(f"{Fore.RED}[!] Invalid VirusTotal API key. Please check config.txt{Style.RESET_ALL}")
            sys.exit()
    except Exception:
        print(f"{Fore.RED}Unexpected error occured.{Style.RESET_ALL}")


    try:
        mode = input("Pick What are you gonna Analyse: \n 1. Hash \n 2. URL \n 3. File \n")
        if mode == "1" or mode.lower() == "hash":
            hash_instance = HashScanner(api_key=settings.get("VT_api_key", None), h_value=input("Provide hash for scanning: ").strip())
            hash_instance.start()
        elif mode == "2" or mode.lower() == "URL":
            url_instance = UrlAnalyser(api_key=settings.get("VT_api_key", None), url=input("Provide URL for scanning: ").strip())
            url_instance.vt_url_lookup()
        elif mode == "3" or mode.lower() == "file":
            file_instance = FileAnalyser(api_key=settings.get("VT_api_key", None), file_path=input("Enter path to file: ").strip())
            file_instance.vt_file_scan()

    except KeyboardInterrupt:
        print("Shutting Down")
    except Exception:
        print(f"{Fore.RED}Unexpected error occured.{Style.RESET_ALL}")

if __name__ == "__main__":
    main()