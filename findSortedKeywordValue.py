import re

def extract_key_value_pairs(input_file, output_file):
    # Liste des mots-clés à rechercher
    keywords = [
        'api key', 'api_key', 'apikey', 'secret key', 'secret_key', 'secretkey',
        'password', 'passwd', 'pwd', 'pass', 'secret', 'token', 'access token',
        'access_token', 'auth token', 'auth_token', 'oauth', 'oauth token',
        'oauth_token', 'aws', 'aws_access_key_id', 'aws_secret_access_key',
        'aws_session_token', 's3', 's3 bucket', 's3_bucket', 'azure',
        'azure_storage_account', 'azure_storage_key', 'firebase', 'firebase_token',
        'firebase_secret', 'ftp', 'ftp password', 'ftp_password', 'ssh', 'ssh key',
        'ssh_key', 'private key', 'private_key', 'database', 'db', 'db_password',
        'database_password', 'stripe', 'stripe_key', 'stripe_secret', 'paypal',
        'paypal_key', 'paypal_secret', 'twilio', 'twilio_token', 'twilio_sid',
        'mailgun', 'mailgun_key', 'sendgrid', 'sendgrid_key', 'github', 'github_token',
        'github_key', 'gitlab', 'gitlab_token', 'gitlab_key', 'slack', 'slack_token',
        'slack_webhook', 'jwt', 'jwt_secret', 'jwt_token', 'encryption', 'encryption_key',
        'cipher', 'cipher_key', 'credentials', 'creds', 'config', 'configuration',
        'settings', 'environment', 'env', '.env', 'production', 'staging', 'development',
        'internal', 'private', 'confidential', 'username', 'user', 'admin', 'root',
        'account', 'acct', 'key', 'apikey', 'api-key', 'bearer', 'authorization',
        'auth', 'signature', 'signed', 'sign', 'cert', 'certificate', 'md5', 'sha1',
        'sha256', 'hash', 'social security', 'ssn', 'personally identifiable information',
        'pii', 'credit card', 'card number', 'cvv', 'cvc', 'oauth_verifier', 'oauth_nonce',
        'oauth_timestamp', 'http_auth', 'http_password', 'client_secret', 'client_id',
        'x-api-key', 'x-auth-token', 'refresh_token', 'id_token', 'basic auth',
        'digest auth', 'csrf_token', 'xsrf_token', 'session', 'cookie'
    ]

    # Créer un motif de recherche pour tous les mots-clés
    pattern = r'\b(' + '|'.join(map(re.escape, keywords)) + r')\s*[=:]\s*(["\']?[\w\-\.]+["\']?)'

    with open(input_file, 'r') as infile, open(output_file, 'w') as outfile:
        for line in infile:
            matches = re.findall(pattern, line, re.IGNORECASE)
            for match in matches:
                outfile.write(f"{match[0]}: {match[1]}\n")

# Utilisation du script
input_file = 'result.txt'
output_file = 'sortedResult.txt'
extract_key_value_pairs(input_file, output_file)
print(f"Les résultats ont été écrits dans {output_file}")
