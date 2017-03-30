import yaml
import dns.resolver
import sys
from collections import Counter
import json
import click


def progressbar(func):
    """
    Decorator that implements a progressbar unless self.quiet is True
    """
    def wrapper(self,iocs):
        if self.quiet:
            return func(self,iocs)
        else:
            progress_total = len(self.blocklists) * len(iocs)
            with click.progressbar(length=progress_total,label='Querying DNSBLs',fill_char='\033[92m#\033[0m',empty_char='\033[31m-\033[0m',bar_template='\033[1m%(label)s  [%(bar)s\033[1m]  %(info)s\033[0m') as self.bar:
                return func(self,iocs)
    return wrapper





class maldnsbl(object):
    """Handles and keeps track of the configuration and reports

    Atributes:
        config (dict): contains all of the iformation gathered from the provided yaml file in a dictionary
        blocklists (list): a list of blocklists listed in the Blocklsits section of the yaml file
        nameservers (list): a list of nameservers in the namservers section of the yaml file; 
            will be the dns server used to query the DNSBLs
        tags (dict): a dictionary where keys are blocklists and values are dictionaries where keys are response
            codes and values are tages that correspond to those response codes
        resolver: a dns.resolver.Resolver object used to resolve the domains
        option_boolean (bool): A flag that determines whether or not a boolean report is being run 
        option_fraction (bool): A flag that determines whether count output should be integer (False) or fractions (True)
        report (dict): contains the report results
        debug (bool): A flag that determines whether or not debugging should be turned on
        bar: a click.progressbar
        quiet (bool): A Flag that determines whether or not to display/proces progress bar

    """
    def __init__(self,yaml_file):
        """Loads configuration and sets intitial values of attributes

        Args:
            yaml_file (str): the yaml file that contains the configuration for the script

        """
        stream = open(yaml_file,'r')
        self.config = yaml.load(stream)
        stream.close()
        self.blocklists = self.config['Blocklists'].keys()
        self.nameservers = self.config['nameservers']
        self.tags = None
        self.generate_tags()
        self.resolver = self.instantiate_resolver()
        self.option_boolean = False
        self.option_fraction = False
        self.report = {}
        self.debug = False
        self.bar = None
        self.quiet = True

    def instantiate_resolver(self):
        """Creates a DNS Resolver Object"""
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = self.nameservers
        return resolver

    def generate_tags(self):
        """Generates tags that correspond to each possible response from blocklists

        Part of the configuration of the maldnsbl instance, this will convert the
        information provided in the configuration file into dictionaries that 
        map response codes (integers 0-14 as far as i know) to tags.
        This is the logic that allows for a more relaxed format for the config file.
        """
        self.tags = {blocklist: {} for blocklist in self.blocklists}
        for blocklist in self.blocklists:
            list_of_tags = self.config['Blocklists'][blocklist]
            for tag in list_of_tags:
                if type(tag) is dict:
                    key = int(str(tag.items()[0][0]).split('.')[-1])
                    value = tag.items()[0][1]
                elif type(tag) is str:
                    if list_of_tags.index(tag) == 0:
                        key = 0
                        value = tag
                    else:
                        key = previous_tag + 1
                        value = tag
                previous_tag = key
                self.tags[blocklist][key] = value

    def checkip(self,ip,blocklist):
        """Checks an IP address against a specified DNSBL

        If the domain does not resolve (the ip being checked is not on the DNSBL),
        then None will be returned.
        If the attribute self.option_boolean is set to True and the domain resolves,
        True will be returned and further analysis of the response will not take place.
        Otherwise, a list of tags that correspond to the response codes will be returned
        see documentation on the configuration file for more details

        Args:
            ip (str): the ip address that will be checked against the DNSBL
            blocklist (str): the domain (DNSBL) that will be queried

        Return:
            Returns True or False or a list of tags
        """
        if not self.quiet:
            self.bar.update(1)
        query = self.reverse_ip(ip) + '.' + blocklist
        if self.debug:
            print 'querying: %s' % query
        try:
            answer = self.resolver.query(query,'A')

            # return True if the option is set to only check if the IP exists on a blacklist
            if self.option_boolean:
                return True

            # else continue to process results
            responses = [str(rr) for rr in answer]
            response_codes = [response.split('.')[-1] for response in responses]
            lookup_table = self.tags[blocklist]
            len_lookup_table = len(lookup_table)
            tags = []
            for response_code in response_codes:
                if len_lookup_table == 1:
                    return [lookup_table.items()[0][1]]
                key = int(response_code)
                try:
                    tags.append(lookup_table[key])
                except:
                    print 'Lookup table doesnt have an entry for %s' % response_code
                    print 'Blocklist: %s' % blocklist
                    print 'IP: %s' % ip
                    sys.exit(1)
            return tags

        except dns.resolver.NXDOMAIN:
            return False

    def reverse_ip(self,ip):
        """Returns the reverse of a given IP address

        Arguments:
        ip -- the ip address to be reversed 
        """

        octet_list = ip.split('.')
        reversed_ip = '.'.join(reversed(octet_list))
        return reversed_ip

    @progressbar
    def boolean(self,iocs=None):
        """Sets self.report to a boolean report and returns it

        A boolean report is a report where the keys are the IOCs and the values are a 
        boolean representation (True or False) that represents whether or not ANY blocklist
        returned a response for the IOC

        Args:
            iocs (list): a python iterable (expecting a list) of IOCs that will be reported on

        Returns:
            dict: The results of the report are saved to self.report, but also returned
        """
        self.option_boolean = True
        for ioc in iocs:
            for blocklist in self.blocklists:
                if self.checkip(ioc,blocklist):
                    self.report[ioc] = True
                    if not self.quiet:
                        self.bar.update(len(self.blocklists) - self.blocklists.index(blocklist) + 1)
                    break
                else:
                    self.report[ioc] = False

        return self.report

    @progressbar
    def count_blocklists(self,iocs=None):
        """Sets self.report to a count_blocklists report and returns it

        A count blocklists report is a report where the keys are the IOCs and the values are an 
        integer that represents how many blocklists returned a response for the IOC

        Args:
            iocs -- a python iterable (expecting a list) of IOCs that will be reported on


        Returns:
            dict: The results of the report are saved to self.report, but also returned
        """
        self.option_boolean = True
        for ioc in iocs:
            count = 0
            for blocklist in self.blocklists:
                if self.checkip(ioc,blocklist):
                    count+=1
            if self.option_fraction:
                fraction = '%s/%s' % (count,len(self.blocklists))
                self.report[ioc] = fraction
            else:
                self.report[ioc] = count

        return self.report

    @progressbar
    def list_tags(self,iocs=None):
        """Sets self.report to a list_tags report and returns it

        A list_tags report is a report where the keys are the IOCs and the values are a
        python list that contains all of the unique tags that correspond to responses for the IOC
        from each of the blocklists

        Args:
            iocs (list): a python iterable (expecting a list) of IOCs that will be reported on

        Returns:
            dict: The results of the report are saved to self.report, but also returned
        """
        self.option_boolean = False
        for ioc in iocs:
            tags = set()
            for blocklist in self.blocklists:
                results = self.checkip(ioc,blocklist)
                if results:
                    tags.update(results)
            self.report[ioc] = list(tags)

        return self.report

    @progressbar
    def count_tags(self,iocs=None):
        """Sets self.report to a list_tags report and returns it

        A count_tags report is a report where the keys are the IOCs and the values are an
        integer that represents the number of unique tags that correspond to responses for the IOC
        from each of the blocklists

        Args:
            iocs (list): a python iterable (expecting a list) of IOCs that will be reported on

        Returns:
            dict: The results of the report are saved to self.report, but also returned
        """
        self.option_boolean = False
        for ioc in iocs:
            tags = []
            for blocklist in self.blocklists:
                results = self.checkip(ioc,blocklist)
                if results:
                    tags.append(results)

            self.report[ioc] = dict(Counter(x for xs in tags for x in set(xs)))

        return self.report





        