import os
import re
import sys

def search_keywords(directory, keywords):
    results = {}
    
    print(f"Searching in directory: {directory}")
    print(f"Number of keywords to search: {len(keywords)}")
    
    if not os.path.exists(directory):
        print(f"Error: Directory {directory} does not exist.")
        return results
    
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith('.js'):
                file_path = os.path.join(root, file)
                print(f"Examining file: {file_path}")
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        lines = f.readlines()
                        for i, line in enumerate(lines, 1):
                            for keyword in keywords:
                                if re.search(r'\b' + re.escape(keyword) + r'\b', line, re.IGNORECASE):
                                    if file_path not in results:
                                        results[file_path] = []
                                    results[file_path].append((keyword, i, line.strip()))
                                    print(f"Found '{keyword}' in {file_path} at line {i}")
                except Exception as e:
                    print(f"Error reading file {file_path}: {str(e)}")
    
    return results

def main():
    directory = './jsfiles'
    if len(sys.argv) > 1:
        directory = sys.argv[1]
    
    keywords = [
        'api key', 'api_key', 'apikey', 'secret key', 'secret_key', 'secretkey',
        'password', 'passwd', 'pwd', 'pass',
        'secret', 'token', 'access token', 'access_token', 'auth token', 'auth_token',
        'oauth', 'oauth token', 'oauth_token',
        'aws', 'aws_access_key_id', 'aws_secret_access_key', 'aws_session_token',
        's3', 's3 bucket', 's3_bucket',
        'azure', 'azure_storage_account', 'azure_storage_key',
        'firebase', 'firebase_token', 'firebase_secret',
        'ftp', 'ftp password', 'ftp_password',
        'ssh', 'ssh key', 'ssh_key', 'private key', 'private_key',
        'database', 'db', 'db_password', 'database_password',
        'mysql', 'postgresql', 'oracle', 'mongodb', 'redis',
        'stripe', 'stripe_key', 'stripe_secret',
        'paypal', 'paypal_key', 'paypal_secret',
        'twilio', 'twilio_token', 'twilio_sid',
        'mailgun', 'mailgun_key',
        'sendgrid', 'sendgrid_key',
        'github', 'github_token', 'github_key',
        'gitlab', 'gitlab_token', 'gitlab_key',
        'slack', 'slack_token', 'slack_webhook',
        'jwt', 'jwt_secret', 'jwt_token',
        'encryption', 'encryption_key', 'cipher', 'cipher_key',
        'credentials', 'creds',
        'config', 'configuration', 'settings',
        'environment', 'env', '.env',
        'production', 'staging', 'development',
        'internal', 'private', 'confidential',
        'hardcoded', 'hard-coded', 'hardcode',
        'backdoor', 'vulnerable', 'vulnerability',
        'sensitive', 'critical',
        'username', 'user', 'admin', 'root',
        'account', 'acct',
        'key', 'apikey', 'api-key', 'bearer',
        'authorization', 'auth',
        'signature', 'signed', 'sign',
        'cert', 'certificate',
        'md5', 'sha1', 'sha256', 'hash',
        'social security', 'ssn', 'personally identifiable information', 'pii',
        'credit card', 'card number', 'cvv', 'cvc',
        'oauth_verifier', 'oauth_nonce', 'oauth_timestamp',
        'http_auth', 'http_password',
        'client_secret', 'client_id',
        'x-api-key', 'x-auth-token',
        'refresh_token', 'id_token',
        'basic auth', 'digest auth',
        'csrf_token', 'xsrf_token',
        'session', 'cookie',
        'analytics', 'tracking',
        'comment', 'todo', 'fixme', 'hack',
        'debug', 'verbose'
    ]
    
    print("Starting search...")
    results = search_keywords(directory, keywords)
    
    if results:
        print("\nKeyword matches found:")
        for file_path, matches in results.items():
            print(f"\nFile: {file_path}")
            for keyword, line_number, line_content in matches:
                print(f"  Line {line_number}: '{keyword}' found in: {line_content}")
    else:
        print("No keyword matches found.")

if __name__ == "__main__":
    main()
