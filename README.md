Information Disclosure Script
Automated information disclosure research tool.

Usage Instructions
Start Burp Suite:

Begin by starting Burp Suite with the proxy enabled.
Scan the Target:

Thoroughly explore the target application using Burp Suite.
Filter the captured traffic to find all JavaScript (.js) files.
Extract JavaScript URLs:

Collect all the URLs of the JavaScript files and save them into a file named jsLink.txt.
Download JavaScript Files:

Download the JavaScript files using wget with the following command:

    wget -P jsfiles -i jsLink.txt --user-agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"

Tip: Use appropriate headers with wget to maximize the chances of downloading all files successfully.

Run the Disclosure Check:

Execute the script to check for dangerous disclosures:
    
  python3 checkDangerousDisclosure.py >> result.txt
  
Find and Sort Keywords:

Run the script to find and sort keyword values:
  python3 findSortedKeywordValue.py

Manual Review:

Manually review the results to identify any sensitive information such as tokens, API keys, etc.
