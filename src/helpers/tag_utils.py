import time
def is_root(name: str):
    """"Is the tag a root name
    Args:
        name (str): tag name
    Returns:
        True if tag is valid; otherwise False
    """

    if name:
        allowed_root_tags = [
            'int',
            'trend',
            'sig',
            'omit',
            'tgt',
            'mal',
            'bhv',
            'thr',
            'review',
            'pwn',
            'code',
            'bookmark'
        ]
        min_root_len = 3
        pos = name.find('.')
        if pos < 0:
            substr = name.lower()
        elif pos >= min_root_len:
            substr = name[:pos].lower()
        else:
            substr = ''
        substr = substr.strip()
        if len(substr) and substr[0] == '#':
            substr = substr[1:]
        if len(substr):
            return substr in allowed_root_tags
    return False



def analyze_name(name):
    """Analyze the name for invalid traits

    Args:
        name (str): tag name
    Returns:
        dict('validCharacters', 'isRoot', 'tree')
    """

    if not name:
        raise ValueError('Missing tag name')

    data = {
        # Does the tag use any invalid characters?
        'validChars': False,

        # Does tag use approved list of root tags
        'isRoot': False,
    }

    allowed_chars = [
        range(ord('a'), ord('z') + 1),
        range(ord('A'), ord('Z') + 1),
        range(ord('0'), ord('9') + 1),
        '.',
        '-',
        '_',
    ]
    str = name.strip().lower()
    tree_name = ''

    # Iterate through the allowed chars. set and determine if a char. matches
    valid_charset = True
    for c in str:
        matches = 0
        for r in allowed_chars:
            if (isinstance(r, range) and ord(c) in r) or (c == r):
                break
            matches += 1
        if matches == len(allowed_chars):  # Not found, so quit
            valid_charset = False
            break
    data['validChars'] = valid_charset
    data['isRoot'] = is_root(str)

    def append(the_name, label_count):
        if label_count:
            if len(the_name):
                if the_name[-1] == '.':
                    add_label = the_name[0:-1]
                else:
                    add_label = the_name
                data['tree'].append(add_label)
                return True
        return False


    if data['validChars'] and data['isRoot']:
        data['status'] = 'success'
        data['tree'] = []
        label_count = 0
        valid_label = True

        for c in str:
            if c == '.':
                if append(tree_name, label_count):
                    label_count = 0
                    tree_name += '.'
                    continue
                valid_label = False
                break
            tree_name += c
            label_count += 1

        if label_count:
            append(tree_name, label_count)

        # Check if label is empty (tag..foo) should fail
        if not valid_label and 'tree' in data:
            del data['tree']
        data['validLabels'] = valid_label

    data['status'] = 'success' if data['isRoot'] and data['validChars'] and data['validLabels'] else 'failure'
    return data

def build_tag_tree_children(tags: list, is_hash_prefix=True) -> (dict, dict):
    """Convert a dictionary of tag values into a separated tag and tree data structure.
    The algorithm reads through a *sorted* list of tags and separates out unique and tree tags.
    Given the input below (without the timestamp component), the output is shown at
    `Tag List` and `Tag Tree`.

    Input := {#int: <unixtime>, #int.level1: 1000000, #int.level2: 1000000, #int.level1.tag1: 1000000,
              #int.level2.tag1: 1000000)
    Tag List := (#int.level1.tag1, #int.level2.tag1)
    Tag Tree := (#int, #int.level1, #int.level2)

    Params:
        tags: a list of (name, timestamp) values

    Returns: (dict, dict) where first is the unique list of tags and second is the tag tree
    """
    def _to_time_str(valu):
        return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(valu / 1000)) if valu else None

    def _to_tuple_time(valu):
        assert isinstance(valu, tuple)
        assert len(valu) == 2
        result = (_to_time_str(valu[0]), _to_time_str(valu[1]))
        return result

    # Sort the tags and then compare two adjacent tags. If the tag_2 (should be longer)
    # is a subset of tag_1, then tag_1 is a root tag
    tags_tree = {}
    for new_tag_index in range(len(tags)): #pylint: disable=consider-using-enumerate
        assert len(tags[new_tag_index]) == 2
        assert isinstance(tags[new_tag_index][0], str)
        assert isinstance(tags[new_tag_index][1], tuple)
        assert tags[new_tag_index][1][0] is None or isinstance(tags[new_tag_index][1][0], int)
        assert tags[new_tag_index][1][1] is None or isinstance(tags[new_tag_index][1][1], int)

        submatch = tags[new_tag_index][0]
        if submatch[-1] != '.':
            submatch += '.' # Append '.' to simulate a tree node
        if new_tag_index + 1 < len(tags) and tags[new_tag_index + 1][0].startswith(submatch):
            tagname = '#' if is_hash_prefix else ''
            tagname += tags[new_tag_index][0]
            tags_tree[tagname] = _to_tuple_time(tags[new_tag_index][1])
    # Copy any tag that is not present in the tag tree
    tags_dict = {}
    for tag in tags:
        tagname = '#' if is_hash_prefix else ''
        tagname += tag[0]
        if tagname not in tags_tree:
            tags_dict[tagname] = _to_tuple_time(tag[1])
    return (tags_dict, tags_tree)
