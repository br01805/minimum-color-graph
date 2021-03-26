from urllib.parse import urlparse
from typing import Tuple
from helpers.indicator_validate import IndicatorValidate

def extract_uri_fqdn(form: str, prop: str) -> Tuple[str, str]:
    """Extract Authority/FQDN from a URI
    Args:
        form (str): A synapse form name (ex: inet:url).
        prop (str): The form value

    Returns: tuple containing the remapped form/prop if form is a URL
    """
    result = (form, prop)
    if form == 'inet:url':
        o = urlparse(prop)
        if o.scheme != 'file' and o.hostname:
            ind_val = IndicatorValidate()
            if ind_val.is_ipv4(o.hostname):
                result = ('inet:ipv4', o.hostname)
            elif ind_val.is_ipv6(o.hostname):
                result = ('inet:ipv6', o.hostname)
            else:
                result = ('inet:fqdn', o.hostname)
    return result

def has_fqdn(form: str, prop: str) -> bool:
    """Determine if a Authority/FQDN or FQDN are present
    Args:
        form (str): A synapse form name (ex: inet:url).
        prop (str): The form value

    Returns: True if the authority is a FQDN or form specifies inet:fqdn
    """
    result = False
    if form == 'inet:url':
        o = urlparse(prop)
        if o.scheme != 'file' and o.hostname:
            ind_val = IndicatorValidate()
            if not ind_val.is_ipaddr(o.hostname):
                result = True
    elif form == 'inet:fqdn':
        result = True
    return result

def has_ipaddr(form: str, prop: str) -> bool:
    """Determine if a Authority/IP address or IP address form present
    Args:
        form (str): A synapse form name (ex: inet:url).
        prop (str): The form value

    Returns: True if the authority is a IP address or form specifies inet:ipv4/ipv6
    """
    result = False
    if form == 'inet:url':
        o = urlparse(prop)
        if o.scheme != 'file' and o.netloc:
            if o.hostname:
                ind_val = IndicatorValidate()
                if ind_val.is_ipaddr(o.hostname):
                    result = True
    elif form in ('inet:ipv4', 'inet:ipv6'):
        result = True
    return result
