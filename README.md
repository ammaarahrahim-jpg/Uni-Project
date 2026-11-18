# Uni-Project
"""
Phishing Email Detector with Risk Scoring
CSIT040 - Modern Computing Skills Project (Project 10)

How it works
------------
1. The user pastes an email/message.
2. The text is scanned for phishing keywords/phrases (case-insensitive).
3. Every occurrence of a keyword adds 1 point to the risk score.
4. The score is classified:
       < 3 points  -> Safe        (Low risk)
       3 - 5       -> Suspicious  (Medium risk)
       > 5         -> High Risk
5. Suspicious words are highlighted in the output.
6. Users can add new keywords (saved in keywords.json for next time).
7. Every checked email is logged to flagged_emails.csv, and session
   statistics are available from the menu.
"""

import csv
import json
import os
import re
from datetime import datetime

KEYWORD_FILE = "keywords.json"
LOG_FILE = "flagged_emails.csv"

DEFAULT_KEYWORDS = [
    "urgent", "verify", "password", "click here", "bank", "account suspended",
    "confirm your identity", "login", "security alert", "limited time",
    "act now", "winner", "prize", "free gift", "credit card", "ssn",
    "update your account", "unusual activity", "immediately", "wire transfer",
    "invoice attached", "expires", "locked", "refund", "gift card",
]

# ANSI colours for highlighting (red + bold)
HIGHLIGHT_START = "\033[1;31m"
HIGHLIGHT_END = "\033[0m"

# Session statistics
stats = {"total": 0, "safe": 0, "suspicious": 0, "high": 0}


# ----------------------------------------------------------------------
# Keyword storage
# ----------------------------------------------------------------------
def load_keywords():
    """Load keywords from file, or fall back to the defaults."""
    if os.path.exists(KEYWORD_FILE):
        try:
            with open(KEYWORD_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, list) and data:
                return sorted(set(k.lower().strip() for k in data if k.strip()))
        except (json.JSONDecodeError, OSError):
            print("Warning: could not read keyword file, using defaults.")
    return sorted(DEFAULT_KEYWORDS)


def save_keywords(keywords):
    with open(KEYWORD_FILE, "w", encoding="utf-8") as f:
        json.dump(sorted(keywords), f, indent=2)


def add_keyword(keywords, new_word):
    """Add a keyword; returns True if it was new."""
    new_word = new_word.lower().strip()
    if not new_word or new_word in keywords:
        return False
    keywords.append(new_word)
    keywords.sort()
    save_keywords(keywords)
    return True


# ----------------------------------------------------------------------
# Core analysis
# ----------------------------------------------------------------------
def _pattern(keyword):
    """Whole-word / whole-phrase regex for a keyword."""
    return r"(?<!\w)" + re.escape(keyword) + r"(?!\w)"


def scan_text(text, keywords):
    """Return {keyword: occurrences} for every keyword found in the text."""
    found = {}
    for kw in keywords:
        count = len(re.findall(_pattern(kw), text, flags=re.IGNORECASE))
        if count:
            found[kw] = count
    return found


def calculate_score(found):
    """Each keyword occurrence adds 1 point."""
    return sum(found.values())


def classify(score):
    """Map a score to a risk level."""
    if score < 3:
        return "Safe"
    if score <= 5:
        return "Suspicious"
    return "High Risk"


def highlight(text, found):
    """Wrap each detected keyword in colour codes."""
    if not found:
        return text
    # Longest first so "click here" wins over a shorter overlapping word
    ordered = sorted(found, key=len, reverse=True)
    combined = "|".join(_pattern(k) for k in ordered)
    return re.sub(
        combined,
        lambda m: f"{HIGHLIGHT_START}{m.group(0)}{HIGHLIGHT_END}",
        text,
        flags=re.IGNORECASE,
    )


def analyze(text, keywords):
    """Full analysis: returns (score, level, found)."""
    found = scan_text(text, keywords)
    score = calculate_score(found)
    return score, classify(score), found


# ----------------------------------------------------------------------
# Logging and statistics
# ----------------------------------------------------------------------
def log_to_csv(text, score, level, found):
    new_file = not os.path.exists(LOG_FILE)
    preview = " ".join(text.split())[:80]
    with open(LOG_FILE, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        if new_file:
            writer.writerow(["timestamp", "risk_level", "score",
                             "keywords_found", "preview"])
        writer.writerow([
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            level,
            score,
            "; ".join(f"{k} x{v}" for k, v in found.items()),
            preview,
        ])


def update_stats(level):
    stats["total"] += 1
    if level == "Safe":
        stats["safe"] += 1
    elif level == "Suspicious":
        stats["suspicious"] += 1
    else:
        stats["high"] += 1


def show_stats():
    print("\n--- Session Statistics ---")
    print(f"Total emails checked : {stats['total']}")
    print(f"Safe                 : {stats['safe']}")
    print(f"Suspicious           : {stats['suspicious']}")
    print(f"High Risk            : {stats['high']}")


# ----------------------------------------------------------------------
# User interface
# ----------------------------------------------------------------------
def read_email():
    """Read a multi-line email; the user finishes by typing END on its own line."""
    print("\nPaste the email text below. Type END on a new line when finished:")
    lines = []
    while True:
        try:
            line = input()
        except EOFError:
            break
        if line.strip().upper() == "END":
            break
        lines.append(line)
    return "\n".join(lines)


def check_email(keywords):
    text = read_email()
    if not text.strip():
        print("No text entered.")
        return

    score, level, found = analyze(text, keywords)

    print("\n=========== RESULT ===========")
    print(f"Risk score : {score}")
    print(f"Risk level : {level}")
    if found:
        print("Keywords   : " + ", ".join(f"{k} (x{v})" for k, v in found.items()))
    else:
        print("Keywords   : none detected")
    print("\nHighlighted message:")
    print("-" * 28)
    print(highlight(text, found))
    print("-" * 28)

    update_stats(level)
    log_to_csv(text, score, level, found)
    print(f"(Saved to {LOG_FILE})")


def show_keywords(keywords):
    print(f"\n--- Keyword list ({len(keywords)}) ---")
    for i in range(0, len(keywords), 3):
        print("  ".join(f"{k:<22}" for k in keywords[i:i + 3]))


def main():
    keywords = load_keywords()
    print("=== Phishing Email Detector ===")

    while True:
        print("\n1. Check an email")
        print("2. Add a new keyword")
        print("3. View keywords")
        print("4. View statistics")
        print("5. Exit")
        try:
            choice = input("Choose an option (1-5): ").strip()
        except EOFError:
            break

        if choice == "1":
            check_email(keywords)
        elif choice == "2":
            word = input("Enter the new keyword or phrase: ")
            if add_keyword(keywords, word):
                print(f"Added '{word.lower().strip()}'.")
            else:
                print("Keyword is empty or already in the list.")
        elif choice == "3":
            show_keywords(keywords)
        elif choice == "4":
            show_stats()
        elif choice == "5":
            show_stats()
            print("Goodbye!")
            break
        else:
            print("Invalid choice, please enter 1-5.")


if __name__ == "__main__":
    main()
