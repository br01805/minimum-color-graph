from urllib.parse import urlparse
import tldextract

def get_url_authority(url: str):
    """Get the URL authority if the string is a URL
    Args:
        url (str): A valid URL string
    Returns: A tuple(form, value) where form can be inet:fqdn, inet:ipv4, inet:ipv6, or None
             None is returned if URL doesn't contain a authority field
    """

    assert url
    result = None
    url_result = urlparse(url)
    if url_result.netloc and url_result.netloc[0] == '[' and ':' in url_result.netloc:
        pos = url_result.netloc.rfind(']')
        result = ('inet:ipv6', url_result.netloc[1:pos])
    elif url_result.hostname:
        tld_result = tldextract.extract(url_result.hostname)
        if tld_result.ipv4:
            result = ('inet:ipv4', tld_result.ipv4)
        else:
            domain_name = tld_result.domain + '.' + tld_result.suffix
            result = ('inet:fqdn', domain_name)
    return result
