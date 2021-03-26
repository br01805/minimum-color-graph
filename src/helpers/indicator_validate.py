import re
from tld import get_tld
from typing import Optional
from urllib.parse import urlparse

class IndicatorValidate:
    """This class contains a list of indicator validation functions that can be used for assert or
     precondition testing."""

    class Matcher:
        """This class specifies a single type of indicator matcher."""

        def __init__(self, patt):
            self.re = re.compile(patt)

        def test(self, val):
            return bool(self.re.match(val))

    patterns_instance = None

    def __init__(self):
        # Create a singleton for the patterns to avoid wasting memory when multiple objects have been created
        if not IndicatorValidate.patterns_instance:
            IndicatorValidate.patterns_instance = {
                'md5': IndicatorValidate.Matcher(r'^[0-9a-fA-F]{32}$'),
                'sha1': IndicatorValidate.Matcher(r'^[0-9a-fA-F]{40}$'),
                'sha256': IndicatorValidate.Matcher(r'^[0-9a-fA-F]{64}$'),
                'sha512': IndicatorValidate.Matcher(r'^[0-9a-fA-F]{128}$'),
                'ipv4': IndicatorValidate.Matcher(r'^[0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}$'),
                'ipv6': IndicatorValidate.Matcher(
                    (r'^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}'
                     r'|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}'
                     r'|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}'
                     r'|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)'
                     r'|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])[.]){3,3}(25[0-5]'
                     r'|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])[.]){3,3}'
                     r'(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$')),
                'fqdn': IndicatorValidate.Matcher(r'^[A-Za-z0-9][A-Za-z0-9-]{0,62}[.]'),
                'fqdn_label': IndicatorValidate.Matcher(r'^[A-Za-z0-9][A-Za-z0-9-]{0,62}$'),
                'syn_guid': IndicatorValidate.Matcher(r'^[0-9a-fA-F]{64}$'),
                'form_guid': IndicatorValidate.Matcher(r'^(guid:)?[0-9a-fA-F]{32}$'),
                'filebytes': IndicatorValidate.Matcher(r'^(guid:[0-9a-fA-F]{32}$|sha256:[0-9a-fA-F]{64}$)'),
                'telephone': IndicatorValidate.Matcher(r'^(?:\+\d{1,3}|0\d{1,3}|00\d{1,2})?(?:\s?\(\d+\))?(?:[-\/\s.]|\d)+$'),
                'email': IndicatorValidate.Matcher(r'^[A-Za-z0-9!#$%&‘*+-/=?^_`.{|}~]{1,64}@'),
                'syn_form': IndicatorValidate.Matcher(r'^[ \t]*[A-Za-z0-9-]+:'),
            }
        self.patterns = IndicatorValidate.patterns_instance

    def is_md5(self, val):
        """Check if value is an MD5 hash"""
        return val and self.patterns['md5'].test(val)

    def is_sha1(self, val):
        """Check if value is an SHA1 hash"""
        return val and self.patterns['sha1'].test(val)

    def is_sha256(self, val):
        """Check if value is an SHA256 hash"""
        return val and self.patterns['sha256'].test(val)

    def is_sha512(self, val):
        """Check if value is an SHA512 hash"""
        return val and self.patterns['sha512'].test(val)

    def is_ipv4(self, val):
        """Check if value is an IPv4 address"""
        return val and self.patterns['ipv4'].test(val)

    def is_ipv6(self, val):
        """Check if value is an IPv6 address"""
        return val and self.patterns['ipv6'].test(val)

    def is_ipaddr(self, val):
        """Check if value is an IPv4 or IPv6 address"""
        return val and (self.is_ipv4(val) or self.is_ipv6(val))

    def is_fqdn(self, val):
        """Check if value is an FQDN"""
        result = False
        if val and len(val) >= 3 and len(val) < 256 and self.patterns['fqdn'].test(val) and self.is_tld(val):
            labels = val.split('.')
            if len(labels) >= 2:
                result = all([len(label) > 0 and len(label) <= 63
                              and label[0] != '-'
                              and self.patterns['fqdn_label'].test(label)
                              for label in labels])
                lastlabel = labels[-1].lower()
                if not self.is_tld(lastlabel):
                    result = False
        return result

    def is_telephone(self, val):
        """Check if value is an email address"""
        return val and self.patterns['telephone'].test(val)

    def is_syn_guid(self, val):
        """Is value match a 'iden' Synapse secondary propery"""
        return val and self.patterns['syn_guid'].test(val)

    def is_form_guid(self, val):
        """Is the property match Synapse GUID
        See Also: https://vertexprojectsynapse.readthedocs.io/en/latest/synapse/userguides/storm_ref_type_specific.html
        """
        return val and self.patterns['form_guid'].test(val)

    def is_syn_form(self, val):
        return val and self.patterns['syn_form'].test(val)

    def check_regval(self, all_str: str, syn_val: str):
        """Check a registry value node is properly formatted

        Returns: val < 0 -> not a registry value
                 val == 0 -> valid registry value syntax
                 val < 0 -> is registry value string, but not properly formatted
        """
        ret = -1
        if all_str.startswith('it:dev:regval'):
            ret = 1
            if syn_val == '"*"' or syn_val == '*' or self.patterns['form_guid'].test(syn_val):
                ret = 1
            # Minimum value is ("A","B")
            elif len(syn_val) < 9:
                ret = 0
            else:
                if syn_val[0] != '(' or syn_val[-1] != ')':
                    ret = 0
                else:
                    re_match = re.match(r'^\("[^"]+"[ ]*,[ ]*"[^"]+"\)', syn_val)
                    if not re_match:
                        ret = 0
        return ret

    def is_syn_value(self, val: str):
        """Check if the VALUE part of Synapse tuple assignment is properly formatted

           Args:
               val: A name=VALUE string. The VALUE is checked for proper escaping and quoting. The
                    'name=' MUST already be validated prior to calling this function

           Returns:
               True if value is properly formatted; otherwise false
        """
        if not val:
            return False

        syn_val = ''
        pos = val.index('=')
        syn_val = val[pos+1:]

        regval_ret = self.check_regval(val, syn_val)
        if regval_ret >= 0:
            return regval_ret > 0

        # Finished copying value after '=' sign now validate
        if len(syn_val) >= 4 and syn_val[0] == '(' and syn_val[-1] == ')':
            return True

        ret = True
        if len(syn_val):
            is_quoted = False
            if len(syn_val) >= 2 and syn_val[0] == '"':
                is_quoted = True
                if syn_val[-1] != '"':
                    ret = False
                else:
                    syn_val = syn_val[1:-1]
            if syn_val:
                char_prev = ''
                char_curr = ''
                for char_curr in syn_val:
                    if (char_curr.isspace() or char_curr == '(' or char_curr == ')') and not is_quoted:
                        ret = False
                        break
                    if char_curr == '"' and char_prev != '\\':
                        ret = False
                        break
                    char_prev = char_curr
            else:
                ret = False
        else:
            ret = False
        return ret

    def is_filebytes(self, val):
        """Check if value is an file:bytes value"""
        return val and self.patterns['filebytes'].test(val)

    def is_email(self, val):
        """Check if value is email address"""
        result = False
        # min valid email is a@a.a
        if val and len(val) >= 4 and len(val) < 64 + 254 and self.patterns['email'].test(val):
            pos = val.find('@')
            if pos > 0:
                fqdn = val[pos+1:]
                if self.is_fqdn(fqdn):
                    result = True
        return result

    def is_url(self, val) -> bool:
        """Is value a URL"""
        result = None
        try:
            o = urlparse(val)
            result = all([o.scheme, o.netloc])
        except ValueError:
            pass
        return result

    def is_tld(self, val):
        try:
            get_tld(val, fix_protocol=True)
        except BaseException:
            return False
        return True

    def match_form(self, val) -> Optional[str]:
        """Check if value is Synapse tuple form string"""
        form = None
        if self.is_ipv4(val):
            form = 'inet:ipv4'
        elif self.is_email(val):
            form = 'inet:email'
        elif self.is_fqdn(val):
            form = 'inet:fqdn'
        elif self.is_md5(val):
            form = 'hash:md5'
        elif self.is_sha1(val):
            form = 'hash:sha1'
        elif self.is_sha256(val):
            form = 'hash:sha256'
        elif self.is_sha512(val):
            form = 'hash:sha512'
        elif self.is_url(val):
            form = 'inet:url'
        return form
