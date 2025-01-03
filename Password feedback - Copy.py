import re
from collections import Counter

# Define a list of common passwords
COMMON_PASSWORDS = [
    "password", "123456", "123456789", "qwerty", "abc123", "letmein", "monkey", "football"
]

def display_progress_bar(percentage):
    """
    Display a progress bar representing password strength.
    :param percentage: Strength percentage (0 to 100)
    """
    bar_length = 20
    filled_length = int(bar_length * percentage // 100)
    bar = '█' * filled_length + '-' * (bar_length - filled_length)
    print(f"[{bar}] {percentage}% strong")

def assess_password_strength(password):
    """
    Evaluate the strength of a password based on defined criteria.
    :param password: Password string to evaluate
    :return: Tuple of checks passed, feedback messages, and strength percentage
    """
    feedback = []
    checks_passed = 0

    # Check if the password is too common
    if password.lower() in COMMON_PASSWORDS:
        return 0, ["Password is too common. Choose a unique password."], 0

    # Check password length
    if len(password) >= 8:
        feedback.append("Good password length.")
        checks_passed += 1
    else:
        feedback.append("Password is too short. Use at least 8 characters.")

    # Check complexity: includes uppercase, lowercase, digits, and special characters
    if (re.search(r'[A-Z]', password) and
        re.search(r'[a-z]', password) and
        re.search(r'[0-9]', password) and
        re.search(r'[!@#$%^&*(),.?":{}|<>]', password)):
        feedback.append("Good password complexity.")
        checks_passed += 1
    else:
        feedback.append("Password lacks complexity. Include uppercase, lowercase, numbers, and special characters.")

    # Check for character uniqueness
    if max(Counter(password).values(), default=0) <= len(password) // 2:
        feedback.append("Good character uniqueness.")
        checks_passed += 1
    else:
        feedback.append("Password has too many repeated characters. Use more unique characters.")

    # Check for sequences like "abc" or "123"
    sequences = ["abcdefghijklmnopqrstuvwxyz", "1234567890"]
    has_sequence = any(seq[i:i+3] in password.lower() for seq in sequences for i in range(len(seq) - 2))
    if not has_sequence:
        feedback.append("No common sequences detected.")
        checks_passed += 1
    else:
        feedback.append("Password contains sequences (e.g., abc, 123). Avoid using sequences.")

    # Calculate strength percentage
    percentage = checks_passed * 25

    # Provide overall feedback based on checks passed
    if checks_passed == 1:
        feedback.append("Your password is weak (25% strong).")
    elif checks_passed == 2:
        feedback.append("Your password is moderately strong (50% strong).")
    elif checks_passed == 3:
        feedback.append("Your password is strong (75% strong).")
    elif checks_passed == 4:
        feedback.append("Your password is strong and good to go (100% strong).")

    return checks_passed, feedback, percentage

def main():
    """
    Main function to assess password strength based on user input.
    """
    print("Password Strength Checker")
    print("Criteria for a strong password:")
    print("1. At least 8 characters in length.")
    print("2. Includes uppercase, lowercase, numbers, and special characters.")
    print("3. Avoids repeated characters.")
    print("4. Does not contain common sequences (e.g., abc, 123).\n")

    password = input("Enter a password to assess: ")

    _, feedback, percentage = assess_password_strength(password)

    print("\nAssessment:")
    for message in feedback:
        print(f"- {message}")

    print("\nPassword Strength Progress Bar:")
    display_progress_bar(percentage)

if __name__ == "__main__":
    main()
