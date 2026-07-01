#!/bin/sh
if [ $# -eq 2 ]; then
    python3 security/run_crawler.py --proxy-host="$1" --proxy-port="$2"
elif [ $# -eq 0 ]; then
    python3 security/run_crawler.py --base-url "https://127.0.0.1:8443"
else
    echo "Error!!"
    echo "-------"
    echo "To run the Crawler for localhost, execute runCrawler.sh with no arguments."
    echo "To run the Crawler for remote host, execute runCrawler.sh with only 2 arguments, proxy-host and proxy-port."
    echo "Example: ./runCrawler.sh 192.168.0.1 53452"
    exit 1
fi
