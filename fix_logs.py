import json
from waf_module.waf import detect_pattern, detect_ai_anomaly  


#loads the dataset, extracts features, trains the Random Forest model, evaluates it, and saves it to a file.

LOG_FILE = "waf_logs.json"

def fix_attack_types():
    try:
        with open(LOG_FILE, "r") as file:
            logs = json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        print("No logs found or file is corrupted.")
        return

    updated_logs = []
    for log in logs:
        data = log.get("data", "")

        # Re-detect attacks using your fixed functions
        pattern_attack = detect_pattern(data)
        ai_suspicious = detect_ai_anomaly(data)

        if pattern_attack:
            if "SQL Injection" in pattern_attack:
                attack_type = "SQL Injection"
            elif "XSS Attack" in pattern_attack:
                attack_type = "XSS Attack"
            else:
                attack_type = "Unknown Attack"
        elif ai_suspicious:
            attack_type = "AI Anomaly"
        else:
            attack_type = "Normal"

        # Update attack_type without touching anything else
        log["attack_type"] = attack_type
        updated_logs.append(log)

    # Save updated logs back
    with open(LOG_FILE, "w") as file:
        json.dump(updated_logs, file, indent=4)

    print("✅ Logs updated successfully without losing timestamps or data.")

if __name__ == "__main__":
    fix_attack_types()
