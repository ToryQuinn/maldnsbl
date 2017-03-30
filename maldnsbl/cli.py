import click
import maldnsbl
from collections import Counter
import json
import sys

# Utlity Functions

def iterate_report(report,sep=': '):
    """Converts an iterable into a string for output

    Will take a list or dicitonary and convert it to a string where
    each item in the iterable is joined by linebreaks (\\n)

    Args:
        report (iterable): the iterable (list or dict) that is to be converted
        sep (str): for dicts, the seperator echoed in between the keys and values

    Returns:
        str: A string that is the report joined by linebreaks (\\n)
    """
    if type(report) is list:
        return '\n'.join(report)
    elif type(report) is dict:
        return '\n'.join(key+sep+str(value) for key,value in report.iteritems())

def false_report(report):
    """Converts a boolean report into a string for output

    Only used when the --boolean option is used.  Converts the boolean
    report into a string that is every key in the boolean report that has a 
    False value, joined by linebreaks (\\n)

    Arguments:
        report (list): the iterable (list or dict) that is to be converted

     Returns:
        str: A string that is the report joined by linebreaks (\\n)    
    """

    return '\n'.join(key for key in report.keys() if not report[key])

def true_report(report):
    """Converts a boolean report into a string for output

    Only used when the --boolean option is used.  Converts the boolean
    report into a string that is every key in the boolean report that has a 
    True value, joined by linebreaks (\\n)

    Arguments:
        report (list): the iterable (list or dict) that is to be converted

     Returns:
        str: A string that is the report joined by linebreaks (\\n)  
    """

    return '\n'.join(key for key in report.keys() if report[key])

@click.command()
@click.option('--input-file', '-f', help='Input file with IOCs to search (Just IPs for now), if not provided, it will attempt to read from stdin',type=click.File('rb'))
@click.option('--ip',help='Single IP to search')
@click.option('--output_file','-o', help='Output File to write output to',type=click.File('wb'))
@click.option('--config','-c', help='Configuration (yaml) File Location, if one is not provided, the config file packaged with maldnsbl will be used',type=click.Path(exists=True))
@click.option('--boolean','report_type', flag_value='boolean',help='Report Type: Checks Blacklists for ANY response from a blacklist and returns either true or false')
@click.option('--count-blocklists', 'report_type',flag_value='count_blocklists',help='Report Type: Counts the number of blocklists that return matches for each IOC')
@click.option('--count-tags','report_type',flag_value='count_tags',help='Report Type: Counts the number of tags returned by the blocklists for each IOC')
@click.option('--list-tags','report_type',flag_value='list_tags',help='Report Type: Will list every tag returned for each IOC')
@click.option('--json','format',flag_value='json',help='Format: the output will be in json format')
@click.option('--true','format',flag_value='true',help='Format: the output will be only the IOCs that returned true in a boolean report (requires --boolean)')
@click.option('--false','format',flag_value='false',help='Format: the output will be only the IOCs that returned false in a boolean report (required --boolean)')
@click.option('--iterate','format',flag_value='iterate',help='Format: the output will be the report line for line rather than as a pyhton object')
@click.option('--csv','format',flag_value='csv',help='Format: the output will be comma seperated values')
@click.option('--fraction',is_flag=True,default=False,help ='Change the format of blocklist counts to fractions of the total (requires --count-blocklists)')
@click.option('--quiet','-q',count=True,help='-q will not echo results, -qq turns off progress bar but will echo the results, -qqq will echo neither (so you would need an ouput file specified')
@click.option('--debug','-d',is_flag=True,default=False,help='Turn debugging on, will break the progress bar')
def main(config,input_file,report_type,format,debug,fraction,quiet,output_file,ip):
    """Uses DNSBL to lookup reputation on IOCs"""

    if not input_file and not ip:
        input_file = [line for line in sys.stdin]
    if ip:
        input_file = [ip]
    if not config:
        config = sys.prefix + '/maldnsbl_config/maldnsbl.yaml'

    mdbl = maldnsbl.maldnsbl(config)
    if debug:
        mdbl.debug = True
    if fraction:
        mdbl.option_fraction = True
    if quiet >= 2:
        mdbl.quiet = True
    else:
        mdbl.quiet = False


    iocs = [line.strip() for line in input_file]

    #run the correct report type
    report = getattr(mdbl,report_type)(iocs)


    if format == 'json':
        output =  json.dumps(report)
    elif format == 'true':
        output = true_report(report)
    elif format == 'false':
        output = false_report(report)
    elif format == 'iterate':
        output = iterate_report(report,': ')
    elif format == 'csv':
        output = iterate_report(report,',')

    else:
        output =  report

    if output_file:
        output_file.write(output)
    if quiet == 0 or quiet ==2:
        click.echo(output)



    

if __name__ == '__main__':
    main()