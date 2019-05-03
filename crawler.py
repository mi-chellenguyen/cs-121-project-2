import logging
import re
from urllib.parse import urlparse
from corpus import Corpus
import os
from lxml import html
from urllib.parse import urljoin
from collections import Counter
import tldextract
logger = logging.getLogger(__name__)

class Crawler:
    """
    This class is responsible for scraping urls from the next available link in frontier and adding the scraped links to
    the frontier
    """

    def __init__(self, frontier):
        self.frontier = frontier
        self.corpus = Corpus()
        
        # analytics information
        self.subdomains_visited = dict()
        self.most_valid_outlinks = "" 
        self.traps_log = []
        self.downloaded_urls = []

    def start_crawling(self):
        """
        This method starts the crawling process which is scraping urls from the next available link in frontier and adding
        the scraped links to the frontier
        """
        while self.frontier.has_next_url():
            url = self.frontier.get_next_url()
            logger.info("Fetching URL %s ... Fetched: %s, Queue size: %s", url, self.frontier.fetched, len(self.frontier))
            url_data = self.fetch_url(url)

            for next_link in self.extract_next_links(url_data):
                if self.corpus.get_file_name(next_link) is not None:
                    if not self.is_valid(next_link): 
                        # add url to list of traps for analytics
                         self.traps_log.append(next_link)
                         
                    if self.is_valid(next_link):
                        self.frontier.add_url(next_link)
                        
                        # add url to downloaded urls for analytics 
                        self.downloaded_urls.append(next_link)
                        
                        # find subdomain of url and add to analytics 
                        extracted_link = tldextract.extract(next_link)
                        if not extracted_link.subdomain in self.subdomains_visited:
                            self.subdomains_visited[extracted_link.subdomain] = 1
                        else:
                            self.subdomains_visited[extracted_link.subdomain] += 1
                            
        
        # store analytics data to files
        downloaded_urls_file = open("downloaded_urls.txt","w+")
        for url in self.downloaded_urls:
            downloaded_urls_file.write(url + '\n')
            
        traps_file = open("traps_log.txt","w+")
        for url in self.traps_log:
            traps_file.write(url + '\n')
            
        subdomains_file = open("subdomains_log.txt","w+")
        for item in self.subdomains_visited.items():
            subdomains_file.write('{:25} count: {}\n'.format(item[0], str(item[1])))
            
    def fetch_url(self, url):
        """
        This method, using the given url, should find the corresponding file in the corpus and return a dictionary
        containing the url, content of the file in binary format and the content size in bytes
        :param url: the url to be fetched
        :return: a dictionary containing the url, content and the size of the content. If the url does not
        exist in the corpus, a dictionary with content set to None and size set to 0 can be returned.
        """
        url_data = {
            "url": url,
            "content": None,
            "size": 0
        }
        
        file_addr = self.corpus.get_file_name(url)
        if file_addr:
            tree = html.parse(file_addr)
            url_data["content"] = html.tostring(tree)
            url_data["size"] = os.stat(file_addr).st_size # obtain content size in bytes
        return url_data
    
    def extract_next_links(self, url_data):
        """
        The url_data coming from the fetch_url method will be given as a parameter to this method. url_data contains the
        fetched url, the url content in binary format, and the size of the content in bytes. This method should return a
        list of urls in their absolute form (some links in the content are relative and needs to be converted to the
        absolute form). Validation of links is done later via is_valid method. It is not required to remove duplicates
        that have already been fetched. The frontier takes care of that.

        Suggested library: lxml
        """
        outputLinks = []
        for link in html.fromstring(url_data["content"]).xpath('//a/@href'):
            abs_url = urljoin(url_data["url"], link) # do absolute url processing
            outputLinks.append(abs_url)
        return outputLinks

    def is_valid(self, url):
        """
        Function returns True or False based on whether the url has to be fetched or not. This is a great place to
        filter out crawler traps. Duplicated urls will be taken care of by frontier. You don't need to check for duplication
        in this method
        """
        parsed = urlparse(url)

        
        if parsed.scheme not in set(["http", "https"]):
            return False
        # check for crawler traps here!

        #check if url too long
        if len(parsed.path) > 150:
            return False

        #calendar traps
        if re.match("^.*calendar.*year=201[012345678].*$", parsed.query.lower()):
        #if re.match("^.*calendar.*year=203.*$", parsed.query.lower()):
            return False


        #weird login that does not help with our exploration
        if re.match("^.*do=login&sectok=.*$", parsed.query.lower()):
            return False

        #specific query trap
        if re.match("^.*start\?do=.*type=sidebyside.*$", url.lower()):
            return False

        # Repeating directories trap
        urlWords = url.split("/")
        urlDict = Counter(urlWords)
        for key in urlWords:
            if urlDict[key] > 2:
                return False
        
        try:
            return ".ics.uci.edu" in parsed.hostname \
                   and not re.match(".*\.(css|js|bmp|gif|jpe?g|ico" + "|png|tiff?|mid|mp2|mp3|mp4" \
                                    + "|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf" \
                                    + "|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso|epub|dll|cnf|tgz|sha1" \
                                    + "|thmx|mso|arff|rtf|jar|csv" \
                                    + "|rm|smil|wmv|swf|wma|zip|rar|gz|pdf)$", parsed.path.lower())

        except TypeError:
            print("TypeError for ", parsed)
            return False

