# InformationDisclosureScript
All about automated information disclosure research


To use this script you need to start burp with proxy, then dive in the whole target victim, filter  js file  and paste it all in a file named jsLink.txt. then python3 checkDangerousDisclosure.py >> result.txt, then python3 findSortedKeywordValue.py, then you need to check manually to see if you found token api key etc...
