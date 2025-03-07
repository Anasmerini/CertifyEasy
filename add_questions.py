# CertifyEasy AI - CSV Question Adder Tool
import csv
import os

# CIA Part 1 Subjects
SUBJECTS = [
    "Foundations of Internal Auditing",
    "Independence and Objectivity",
    "Proficiency and Due Professional Care",
    "Quality Assurance and Improvement Program",
    "Governance, Risk Management, and Control",
    "Fraud Risks"
]

# File path for QBANK_CIA1.csv
CSV_FILE = r"C:\Users\a.merini\Desktop\CertifyEasy AI\QBANK_CIA1.csv"

def escape_quotes(text):
    """Escape internal double quotes by doubling them."""
    return text.replace('"', '""')

def add_question_to_csv():
    """Prompt for question elements and append to CSV."""
    # Check if file exists, create with headers if not
    headers = ["subject", "question", "option1", "option2", "option3", "option4", "answer", "explanation"]
    file_exists = os.path.exists(CSV_FILE)
    
    with open(CSV_FILE, 'a', newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=headers)
        if not file_exists:
            writer.writeheader()
        
        while True:
            print("\nEnter a new CIA Part 1 question (leave subject blank to finish):")
            
            # Subject
            print("Subjects:", ", ".join(SUBJECTS))
            subject = input("Subject: ").strip()
            if not subject:
                break
            if subject not in SUBJECTS:
                print("Invalid subject! Please choose from the list.")
                continue
            
            # Question
            question = input("Question: ").strip()
            if not question:
                print("Question cannot be empty!")
                continue
            
            # Options
            options = []
            for i in range(1, 5):
                option = input(f"Option {i}: ").strip()
                if not option:
                    print(f"Option {i} cannot be empty!")
                    break
                options.append(option)
            if len(options) != 4:
                print("All 4 options are required!")
                continue
            
            # Answer
            answer = input("Correct Answer (exact text of one option): ").strip()
            if answer not in options:
                print("Answer must match one of the options exactly!")
                continue
            
            # Explanation
            explanation = input("Explanation: ").strip()
            if not explanation:
                print("Explanation cannot be empty!")
                continue
            
            # Format row with escaped quotes
            row = {
                "subject": f'"{escape_quotes(subject)}"',
                "question": f'"{escape_quotes(question)}"',
                "option1": f'"{escape_quotes(options[0])}"',
                "option2": f'"{escape_quotes(options[1])}"',
                "option3": f'"{escape_quotes(options[2])}"',
                "option4": f'"{escape_quotes(options[3])}"',
                "answer": f'"{escape_quotes(answer)}"',
                "explanation": f'"{escape_quotes(explanation)}"'
            }
            
            # Write to CSV
            writer.writerow(row)
            print(f"Added question to {CSV_FILE} successfully!")
            
            # Ask to continue
            if input("\nAdd another question? (y/n): ").lower() != 'y':
                break

    print(f"\nFinished adding questions. Check {CSV_FILE} for your updates!")

if __name__ == "__main__":
    print("Welcome to CertifyEasy AI - CSV Question Adder Tool")
    add_question_to_csv()