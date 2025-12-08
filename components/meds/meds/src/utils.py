import yaml

def load_yaml(file_path: str):
    """
    Load a Kubernetes YAML manifest and return a Python dictionary.
    """
    try:
        with open(file_path, "r") as f:
            content = yaml.safe_load(f)
            if content is None:
                print(f"[WARNING] YAML file is empty or invalid: {file_path}")
            return content
    except FileNotFoundError:
        print(f"[ERROR] File not found: {file_path}")
        return None
    except yaml.YAMLError as e:
        print(f"[ERROR] YAML parsing error in {file_path}:")
        print(e)
        return None
    except Exception as e:
        print(f"[ERROR] Could not load YAML file: {file_path}")
        print(e)
        return None
    
import json
from datetime import datetime
import os

def save_report(report: dict, output_path: str = None):
    """
    Save the validation report as a JSON file.
    If no path given, store it in reports/ with timestamp.
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    if output_path is None:
        output_path = f"reports/validation-{timestamp}.json"

    with open(output_path, "w") as f:
        json.dump(report, f, indent=4)
    print(f"[INFO] Report saved to {output_path}")

from colorama import Fore, Style

def report_print(result: dict):
    """
    Print validation results in a human-readable format with colors.
    """
    status = result["status"]
    risk = result["risk_score"]
    threshold = result["risk_threshold"]
    env = result["environment"]
    reasons = result["reasons"]

    print("\n================ VALIDATION REPORT ================\n")

    if status == "PASS":
        print(Fore.GREEN + f"✔ STATUS: PASS" + Style.RESET_ALL)
    else:
        print(Fore.RED + f"✘ STATUS: FAIL" + Style.RESET_ALL)

    print(f"Environment: {env}")
    print(f"Risk Score: {risk}")
    print(f"Env Threshold: {threshold}")

    print("\nReasons:")
    if len(reasons) == 0:
        print(Fore.GREEN + "  ✔ No issues detected" + Style.RESET_ALL)
    else:
        for r in reasons:
            print(Fore.RED + f"  - {r}" + Style.RESET_ALL)

    print("\n===================================================\n")


