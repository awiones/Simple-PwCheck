#!/usr/bin/env ruby

require 'digest'
require 'securerandom'
require 'io/console'
require 'clipboard'
require 'date'

COMMON_PASSWORD_FILE = 'file/commonpw.txt'
BREACHED_PASSWORD_FILE = 'file/breached_passwords.txt'
PASSWORD_HISTORY_FILE = 'file/password_history.txt'
PASSWORD_EXPIRATION_DAYS = 90

def load_common_passwords
  return [] unless File.exist?(COMMON_PASSWORD_FILE)
  File.read(COMMON_PASSWORD_FILE).split("\n").map(&:strip).map(&:downcase)
end

def load_breached_passwords
  return [] unless File.exist?(BREACHED_PASSWORD_FILE)
  File.read(BREACHED_PASSWORD_FILE).split("\n").map(&:strip).map(&:upcase)
end

def load_password_history
  return [] unless File.exist?(PASSWORD_HISTORY_FILE)
  File.read(PASSWORD_HISTORY_FILE).split("\n").map(&:strip)
end

COMMON_PASSWORDS = load_common_passwords
BREACHED_PASSWORDS = load_breached_passwords
PASSWORD_HISTORY = load_password_history

def colorize(text, color_code)
  "\033[#{color_code}m#{text}\033[0m"
end

def check_breach(password)
  sha1 = Digest::SHA1.hexdigest(password).upcase
  BREACHED_PASSWORDS.include?(sha1)
end

def calculate_entropy(password)
  charset_size = 0
  charset_size += 26 if password =~ /[a-z]/
  charset_size += 26 if password =~ /[A-Z]/
  charset_size += 10 if password =~ /\d/
  charset_size += 32 if password =~ /[@#\$%\^&\*]/
  password.length * Math.log2(charset_size)
end

def generate_similar_passwords(original_password)
  variations = []

  variations << original_password + '123'
  variations << original_password + '!@#'
  variations << original_password.reverse
  variations << original_password.gsub(/[aeiou]/, '1') 

  variations << original_password + SecureRandom.random_number(1000).to_s
  variations << original_password.capitalize
  variations << original_password.upcase
  variations << original_password.downcase + SecureRandom.hex(2) 

  variations
end

def generate_strong_password(length = 12, special_chars = true)
  chars = ('a'..'z').to_a + ('A'..'Z').to_a + ('0'..'9').to_a
  chars += ['@', '#', '$', '%', '^', '&', '*'] if special_chars
  password = (0...length).map { chars.sample }.join
  password
end

def strength_meter(entropy)
  case entropy
  when 0..40
    "[#{'=' * (entropy / 8).to_i}] Weak"
  when 41..60
    "[#{'=' * (entropy / 8).to_i}] Moderate"
  else
    "[#{'=' * (entropy / 8).to_i}] Strong"
  end
end

def check_password_expiration(password)
  expiration_date = Date.today - PASSWORD_EXPIRATION_DAYS
  if PASSWORD_HISTORY.include?(password)
    last_used_date = Date.parse(PASSWORD_HISTORY.find { |pw| pw == password })
    if last_used_date < expiration_date
      colorize("Password expired. Please change your password.", 31)
    else
      colorize("Password is recent.", 32)
    end
  else
    colorize("Password history not available.", 33)
  end
end

def suggest_similar_passwords(original_password)
  puts "Here are some strong password suggestions similar to your input:"

  similar_passwords = generate_similar_passwords(original_password)
  min_length = [8, original_password.length].max 

  similar_passwords.each do |password|
    next if password.length < min_length 

    strength_msg = check_password_strength(password)
    entropy = calculate_entropy(password)
    
    next if strength_msg.include?("must contain") || strength_msg.include?("at least") 

    color = strength_msg.include?("Strong") ? 32 : (strength_msg.include?("Moderate") ? 33 : 31)
    puts "#{password} - #{colorize(strength_msg + ". Entropy: #{entropy.round(2)} bits.", color)}"
  end
end

def check_password_strength(password)
  return colorize("Password must be at least 8 characters long.", 31) if password.length < 8

  has_upper = password =~ /[A-Z]/
  has_lower = password =~ /[a-z]/
  has_digit = password =~ /\d/
  has_special = password =~ /[@#\$%\^&\*]/

  unless has_upper && has_lower && has_digit && has_special
    return colorize("Password must contain at least one uppercase letter, one lowercase letter, one digit, and one special character.", 31)
  end

  entropy = calculate_entropy(password)
  strength_msg = if entropy < 40
                   colorize("Weak password", 31)
                 elsif entropy < 60
                   colorize("Moderate password", 33)
                 else
                   colorize("Strong password", 32)
                 end

  strength_meter_msg = strength_meter(entropy)
  "#{strength_msg} #{strength_meter_msg}"
end

def check_password_safety(password)
  strength_msg = check_password_strength(password)
  puts strength_msg

  if strength_msg.include?("must contain") || strength_msg.include?("at least")
    return
  end

  if COMMON_PASSWORDS.include?(password.downcase)
    puts colorize("Password is weak: it's a common password.", 31)
  end

  if check_breach(password)
    puts colorize("Password is compromised in known data breaches.", 31)
  end

  suggest_similar_passwords(password)
end

def encrypt_password(encryption_type, password)
  case encryption_type.downcase
  when 'md5'
    Digest::MD5.hexdigest(password)
  when 'sha1'
    Digest::SHA1.hexdigest(password)
  when 'sha256'
    Digest::SHA256.hexdigest(password)
  when 'sha512'
    Digest::SHA512.hexdigest(password)
  when 'bcrypt'
    require 'bcrypt'
    BCrypt::Password.create(password)
  when 'argon2'
    require 'argon2'
    Argon2::Password.create(password)
  else
    colorize("Invalid encryption type. Use --help for available options.", 31)
  end
end

def show_help
  puts <<-HELP
                          USAGE GUIDE
                         -------------
Command                           | Description
----------------------------------|------------------------------------
--help                            | Show this help message
--pw {password}                   | Check password strength
--encrypte {type} {password}      | Encrypt password
--suggest {password}              | Generate a strong password
--history {password}              | Check if the password is recent or expired
--generate {length}               | Generate a strong password with specified length

Encryption types:
  - md5
  - sha1
  - sha256
  - sha512
  - bcrypt
  - argon2
  HELP
end

def parse_arguments
  if ARGV.length < 1
    puts colorize("Use --help for usage instructions.", 31)
    exit
  end

  case ARGV[0]
  when '--pw'
    if ARGV.length != 2
      puts colorize("Usage: --pw {password}", 31)
      exit
    end
    :password
  when '--encrypte'
    if ARGV.length != 3
      puts colorize("Usage: --encrypte {type} {password}", 31)
      exit
    end
    :encryption
  when '--suggest'
    if ARGV.length != 2
      puts colorize("Usage: --suggest {password}", 31)
      exit
    end
    :suggest
  when '--history'
    if ARGV.length != 2
      puts colorize("Usage: --history {password}", 31)
      exit
    end
    :history
  when '--generate'
    if ARGV.length != 2
      puts colorize("Usage: --generate {length}", 31)
      exit
    end
    :generate
  when '--help'
    show_help
    exit
  else
    puts colorize("Invalid option. Use --help for usage instructions.", 31)
    exit
  end
end

def main
  action = parse_arguments

  case action
  when :password
    password = ARGV[1]
    check_password_safety(password)
  when :encryption
    encryption_type = ARGV[1]
    password = ARGV[2]
    encrypted_password = encrypt_password(encryption_type, password)
    puts colorize("Encrypted Password (#{encryption_type}): #{encrypted_password}", 36)
  when :suggest
    suggest_similar_passwords(ARGV[1])
  when :history
    puts check_password_expiration(ARGV[1])
  when :generate
    length = ARGV[1].to_i
    puts "Generated Password: #{generate_strong_password(length)}"
  end
end

main
