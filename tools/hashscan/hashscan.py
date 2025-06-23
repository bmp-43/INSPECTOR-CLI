from colorama import Fore, Style

check = ""
fail = 0

def bcrypt_check():
    global fail
    if check.startswith(("$2a$", "$2b$", "$2y$")) and len(check) == 60:
        print(f"{Fore.BLUE}Provided hash is bcrypt{Style.RESET_ALL}")
    else:
        fail += 1

def md5_ntlm_check():
    global fail
    if len(check) == 32 and all(c in "0123456789abcdefABCDEF" for c in check):
        if check.isupper():
            print(f"{Fore.BLUE}Likely NTLM (uppercase hex){Style.RESET_ALL}")
        elif check.islower():
            print(f"{Fore.BLUE}Likely MD5 (lowercase hex){Style.RESET_ALL}")
        else:
            print(f"{Fore.BLUE}Could be either MD5 or NTLM — indistinguishable without context.{Style.RESET_ALL}")
    else:
        fail += 1

def sha_check():
    global fail
    if len(check) == 40 and all(c in "0123456789abcdefABCDEF" for c in check):
        print(f"{Fore.BLUE}The hash you provided is likely SHA1 (or possibly RIPEMD-160){Style.RESET_ALL}")
    elif len(check) == 64 and all(c in "0123456789abcdefABCDEF" for c in check):
        print(f"{Fore.BLUE}The hash you provided is likely SHA256 (possibly SHA3-256, indistinguishable without context){Style.RESET_ALL}")
    elif len(check) == 128 and all(c in "0123456789abcdefABCDEF" for c in check):
        print(f"{Fore.BLUE}The hash you provided is likely SHA512{Style.RESET_ALL}")
    else:
        fail += 1

def mysql5_check():
    global fail
    if len(check) == 41 and check.startswith("*"):
        body = check[1:]
        if all(c in "0123456789ABCDEF" for c in body):
            print(f"{Fore.BLUE}The hash you provided is likely MySQL 5.x{Style.RESET_ALL}")
        else:
            fail += 1
    else:
        fail += 1

def crc32_check():
    global fail
    if len(check) == 8 and all(c in "0123456789abcdefABCDEF" for c in check):
        print(f"{Fore.BLUE}The hash you provided is likely CRC32 (non-cryptographic){Style.RESET_ALL}")
    else:
        fail += 1

def start():
    global check, fail
    try:
        while True:
            check = input("Provide hash for scanning: ").strip()
            if not check:
                print(f"{Fore.RED}Hash cannot be empty. Try again.{Style.RESET_ALL}")
                continue
            fail = 0  
            bcrypt_check()
            md5_ntlm_check()
            sha_check()
            mysql5_check()
            crc32_check()
            if fail < 5:
                break 
            else:
                print(f"{Fore.RED}Unrecognized hash. Please try again.{Style.RESET_ALL}")
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Scan cancelled by user.{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}An unexpected error occurred: {e}{Style.RESET_ALL}")

if __name__ == "__main__":
    start()

