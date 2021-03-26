#import ast
from typing import Union
import re
import helpers.http_errors as errors

PATTERNS = {'scheme': re.compile('^[a-zA-Z]{3,10}://'),
            }

def _should_quoted_escape(value: str):
    """Check if value must be quoted/escaped
    Args:
        value: the string value to be checked for quoting

    Returns: True if value must be quoted; otherwise False
    """
    result = False
    if (value and isinstance(value, str)):
        if any(c.isspace() or c in ('(', ')', '"', ',', '[', ']', '{', '}') for c in value):
            result = True
        elif  PATTERNS['scheme'].match(value): # Storm seems to require URLs to be quoted
            result = True
    return result

def _backslashify(form: str, value: str):
    """Escape a backslash if necessary to match Storm behavior

       The Storm query parser has a difference in behavior for inet:url verses other string-based
       node types. For URLs, any backslash must be changed into a quad character (\\\\) to be
       properly handled.

       Args:
           form: the Synapse form (inet:ipv4)
           value: the value associated with form

       Returns: The original or modified 'backslashed' string
    """
    if form == 'inet:url':
        try:
            # Avoid modifying/mutating the string if necessary
            pos = value.index('\\')
            new_value = value[:pos]
            while pos < len(value):
                if value[pos] == '\\':
                    new_value += '\\\\'
                else:
                    new_value += value[pos]
                pos += 1
            return new_value
        except ValueError:
            pass
    return value # Unmodified original string

def parse(form: str, value: str):
    """Build a proper name=value quoted Storm string
       Args:
           form: the Synapse form (inet:ipv4)
           value: the value associated with form

        Returns: a "name=value" string that has been correct escaped to pass as a storm query value
    """
    assert form
    composite_forms = (
        'inet:dns:a',
    )
    composite_forms_set = None
    if not composite_forms_set:
        composite_forms_set = frozenset(composite_forms)

    copy_raw = False
    def is_tuple_form():
        """Check if form name match a "comp" type.
           If it's a composite type, then value shouldn't be quoted. It's assumed that the tuple values are
           properly quoted (ex: inet:dns:a=(www.example.com, 23.23.23.23)
        """
        return isinstance(value, str) and len(value) >= 3 and\
               value[0] == '(' and value[-1] == ')' and form in composite_forms_set

    if not is_tuple_form():
        new_value = _backslashify(form, value)
        if _should_quoted_escape(new_value):
            escaped_val = new_value.replace('"', r'\"')
            ret = f'{form}="{escaped_val}"'
        else:
            copy_raw = True
    else:
        copy_raw = True
        new_value = value
    if copy_raw:
        if new_value:
            ret = f'{form}={new_value}'
        else:
            ret = f'{form}=""'
    return ret

def escape(value: str):
    """Build a escaped value for quoted Storm string
       Args:
           value the value associated with form

        Returns: a value string that has been correctly escaped and can be passed as a storm query value
    """
    if _should_quoted_escape(value):
        escaped_val = value.replace('"', r'\"')
        ret = f'"{escaped_val}"'
    else:
        ret = value
    return ret

def _skip_to_end_string(value, pos):
    """Skip past the word [,] seperator"""
    new_pos = pos
    while new_pos < len(value):
        if value[new_pos] == ',':
            new_pos += 1 # move past word terminator
            break
        if value[new_pos] == ')':
            break
        new_pos += 1
    return new_pos

def _grab_string_token(value, pos):
    """Grab the next word or string token from the input"""

    def parse_int(valu):
        try:
            result = int(valu)
        except ValueError:
            result = valu
        return result

    token = ''
    check_int = False
    new_pos = pos
    while new_pos < len(value) and value[new_pos] == ' ':
        new_pos += 1

    if value[new_pos] == '(':
        new_pos, word1 = _grab_string_token(value, new_pos + 1)
        if len(word1) and new_pos < len(value):
            new_pos, word2 = _grab_string_token(value, new_pos)
            if len(word2) and new_pos < len(value):
                if value[new_pos] == ')':
                    new_pos = _skip_to_end_string(value, new_pos + 1)
                return new_pos, (word1, word2)

    if value[new_pos] == '"' or value[new_pos] == "'":
        new_pos += 1
        found_quote = False
        while new_pos < len(value):
            if value[new_pos] == '\\' and new_pos + 1 < len(value):
                token += value[new_pos + 1]
                pos += 1
            elif value[new_pos] == '"' or value[new_pos] == "'":
                found_quote = True
                break
            else:
                token += value[new_pos]
            new_pos += 1
        if not found_quote:
            raise SyntaxError('Missing quote')
        new_pos = _skip_to_end_string(value, new_pos)
    else:
        # Grab a [word, number]
        check_int = True
        while new_pos < len(value):
            if value[new_pos] == '\\' and new_pos + 1 < len(value):
                new_pos += 1
                token += value[new_pos]
            elif value[new_pos] == ' ' or value[new_pos] == '\t':
                new_pos = _skip_to_end_string(value, new_pos)
                break
            elif value[new_pos] == ',' or value[new_pos] == ')':
                break
            else:
                token += value[new_pos]
            new_pos += 1

    if value[new_pos] == ',':
        new_pos += 1

    if check_int:
        token = parse_int(token)
    return new_pos, token

def parse_name_value(field: str) -> (str, Union[str, tuple]):

    """Parse a storm name=value header value

    Args:
        field (str): A Synapse form=property field from an Tufos API.

    Returns: This returns either the raw string or a deserialized 'comp' or tuple value as a Python data structure.
    """
    assert isinstance(field, str)
    pos = field.find('=')
    if pos < 0:
        raise errors.ParameterError((field), 'Invalid name value string', -4000)
    name = field[:pos].strip()
    valu = field[pos+1:]
    # Check for a comp value and parse the two values
    if len(valu) >= 4 and valu[0] == '(' and valu[-1] == ')':
        new_pos, word1 = _grab_string_token(valu, 1)
        if new_pos + 1 < len(valu):
            new_pos, word2 = _grab_string_token(valu, new_pos)
            valu = (word1, word2)
        else:
            valu = '(' + word1 + ')' # Wasn't a true comp value
    elif len(valu) >= 3 and valu[0] == '"' and valu[-1] == '"':
        valu = valu[1:-1]
    if name == 'inet:whois:recns' and isinstance(valu, tuple):
        valu2 = tuple(valu[1].split('='))
        if len(valu2) == 2:
            valu = (valu[0], valu2)
    assert isinstance(name, str)
    return name, valu
