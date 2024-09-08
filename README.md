# Simple-PwCheck

## Description

The Password Checker is a Ruby-based command-line tool designed to evaluate and enhance password security. It offers a suite of functionalities to help users assess the strength of their passwords, ensure they are not common or compromised, and generate strong alternatives.

In today's digital age, having a robust password is crucial for safeguarding personal and sensitive information. This tool aims to simplify the process of creating and managing secure passwords by providing real-time feedback on password strength and safety. It leverages various encryption algorithms to secure passwords and offers insightful suggestions to help users adopt better practices for password security.

### Key Features

- **Password Strength Analysis**: Assess the strength of a password based on criteria such as length, character diversity (uppercase, lowercase, digits, special characters), and entropy. The tool provides feedback on how to improve weak passwords and highlights potential security risks.

- **Encryption Options**: Encrypt passwords using popular hashing algorithms, including MD5, SHA1, SHA256, SHA512, BCrypt, and Argon2. These encryption options help secure passwords before storage or transmission.

- **Password Suggestions**: Generate password suggestions that are similar to the user's input but meet the necessary security requirements. This feature helps users create passwords that are both secure and easy to remember.

- **Password Expiration Check**: Check if a password has been used recently or if it has expired based on a historical record. This helps in enforcing password rotation policies and maintaining up-to-date security practices.

- **Password Generation**: Create strong, random passwords of a specified length. This feature is useful for generating new passwords that meet security requirements without having to come up with them manually.

## Installation

To get started with the Password Checker, follow these steps:

1. **Clone the Repository**:

    ```bash
    git clone https://github.com/awiones/Simple-PwCheck.git
    cd Simple-PwCheck
    chmod +x password_checker.rb
    ./password_checker.rb --help
    ```

2. **Install Dependencies**:

    Ensure you have Bundler installed. If not, install it with:

    ```bash
    gem install bundler
    ```

    Then install the required gems:

    ```bash
    gem install bcrypt argon2
    ```

## Usage

The Password Checker provides several commands for different functionalities. Use the following commands:

    # Check Password Strength
    ./password_checker.rb --pw {password}

    # Encrypt Password
    ./password_checker.rb --encrypte {type} {password}

    # Generate Strong Password
    ./password_checker.rb --generate {length}

    # Check Password History
    ./password_checker.rb --history {password}

    # Suggest Strong Passwords
    ./password_checker.rb --suggest {password}

    # Display Help
    ./password_checker.rb --help

## License

This project is licensed under the GNU 3.0 License. See the [LICENSE](LICENSE) file for details.

---

Made with ❤️ by Awiones

