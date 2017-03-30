# MalDNSBL 
Reputation Checker for IPs

This module allows the quick and easy lookup of a single or multiple IPs
against a list of blocklists provided in the default configuration file
or a file passed to the maldnsbl object.  You can use the module as a command
line tool or import it to use in your own projects.  The module supports multiple
types of report types (boolean, blocklist-count,count-tags,list-tags) which are
explained in more depth in the documentation.  The command line tool accepts file input,
single ip input, and stdin if neither are provided.

##Examples

The likely the most common use of this tool would be to read from an input file
of IP addresses (where each IP is on its own line) and output to the terminal or an ouput file the
results in csv format.
```
    maldnsbl -f ips.txt --count-blocklists --fraction --iterate
    Querying DNSBLs  [####################################]  100%             
    79.157.17.112: 2/17
    37.213.27.48: 0/17
    198.50.177.221: 1/17
    179.125.189.124: 0/17
    63.243.252.196: 0/17
    79.137.72.43: 0/17
    167.114.80.146: 1/17 
    ```

If you want to get the same report in csv format and you don't want to echo to the screen
you could save the output to a file instead.

```
maldnsbl -f ips.txt --counton --iterate -q -o output.csv --csv
Querying DNSBLs  [####################################]  100% 
cat output.csv
79.157.17.112,2/17
37.213.27.48,0/17
198.50.177.221,1/17
179.125.189.124,0/17
63.243.252.196,0/17
79.137.72.43,0/17
167.114.80.146,1/17
```

If you don't want the progress bar to echo to the screen, you can pass -qq.
You can also redirect the output to stdout instead of passing an ouput file.
(useful if you're integrating this will other command line tools).
You can also pass -qqq to echo niether, but then you would need to make sure you pass
an output file using --output-file in order to see your results after the tool is run

```
maldnsbl -f ips.txt --counton --iterate -qq --csv > output.
cat output.csv
79.157.17.112,2/17
37.213.27.48,0/17
198.50.177.221,1/17
179.125.189.124,0/17
63.243.252.196,0/17
79.137.72.43,0/17
167.114.80.146,1/17
```
##Other Useful Examples
```
printf "127.0.0.2" | maldnsbl --boolean --csv
Querying DNSBLs  [####################################]  100%
127.0.0.2,True
pbpaste | maldnsbl --list-tags --iterate #(on OSX)
xclip -o | maldnsbl --list-tags --iterate #(on linux)
Querying DNSBLs  [####################################]  100%             
127.0.0.2: ['open_http_proxy', 'CABL', 'XBL', 'malspam', 'BABL', 'zombie', 'amavis', 'open_smtp_relay', 'STABL', 'open_socks_proxy', 'crawler']
maldnsbl --input-file ips.txt --json --count-blocklists
Querying DNSBLs  [####################################]  100%             
{"79.157.17.112": 2, "37.213.27.48": 0, "198.50.177.221": 1, "179.125.189.124": 0, "63.243.252.196": 0, "79.137.72.43": 0, "167.114.80.146": 1}
maldnsbl --input-file ips.txt --csv  --count-tags -q > output.txt
cat output.txt
79.157.17.112,{'ssh': 1, 'CABL': 1}
37.213.27.48,{}
198.50.177.221,{'CABL': 1}
179.125.189.124,{}
63.243.252.196,{}
79.137.72.43,{}
167.114.80.146,{'CABL': 1}
maldnsbl --input-file ips.txt --csv  --count-tags -qq -o output.txt
cat output.txt
79.157.17.112,{'ssh': 1, 'CABL': 1}
37.213.27.48,{}
198.50.177.221,{'CABL': 1}
179.125.189.124,{}
63.243.252.196,{}
79.137.72.43,{}
167.114.80.146,{'CABL': 1}
```


##Todo
* Implement Threading for large jobs
* Add support for other types of IOCs
* Add logic in the yaml file for keeping track of different types of IOC DNSBL
