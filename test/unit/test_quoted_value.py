import pytest
import helpers.http_errors as errors
import helpers.quoted_storm_value as qsv

class TestParseValue:
    def test_parse_escaped_normal(self):
        result = qsv.escape('word1')
        assert result == 'word1'

        result = qsv.escape('word1,word2')
        assert result == '"word1,word2"'

        result = qsv.escape('word1 word2')
        assert result == '"word1 word2"'

    def test_parse_normal(self):
        result = qsv.parse('field', 'value')

    def test_parse_double_words(self):
        result = qsv.parse('field', 'word1 word2')

    def test_parse_quoted(self):
        result = qsv.parse('field', '"value"')

    def test_parse_quoted_double_word(self):
        result = qsv.parse('field', 'word1 "word2"')
        assert result == 'field="word1 \\"word2\\""'

    def test_parse_empty(self):
        result = qsv.parse('field', '')
        assert result == 'field=""'

    def test_parse_escaped_string(self):
        """Run a test that does not change the backslash"""
        result = qsv.parse('field', 'name\\')
        assert result == 'field=name\\'

    def test_parse_escaped_url(self):
        result = qsv.parse('inet:url', 'name\\')
        assert result == 'inet:url=name\\\\'

    def test_parse_escaped_word2(self):
        result = qsv.parse('inet:url', 'name\\,name2')
        assert result == 'inet:url="name\\\\,name2"'

    def test_parse_escaped_word3(self):
        result = qsv.parse('inet:url', 'name\\, name2')
        assert result == 'inet:url="name\\\\, name2"'

    def test_parse_escaped_word3(self):
        result = qsv.parse('inet:url', 'name\\" name2')
        assert result == 'inet:url="name\\\\\\" name2"'

    def test_parse_inet_dnsa(self):
        result = qsv.parse('inet:dns:a', '(www.example.com, 23.23.23.23)')
        assert result == 'inet:dns:a=(www.example.com, 23.23.23.23)'

    def test_parse_generic_str(self):
        result = qsv.parse('it:dev:str', '(hello, world)')
        assert result == 'it:dev:str="(hello, world)"'

    def test_parse_name_value_simple(self):
        name, value = qsv.parse_name_value('inet:fqdn=www.example.com')
        assert (name, value) == ('inet:fqdn', 'www.example.com')

    def test_parse_name_value_compound(self):
        """Test a tuple form compound value"""

        name, value = qsv.parse_name_value('inet:test=(word1, word2)')
        assert (name, value) == ('inet:test', ('word1', 'word2'))

        name, value = qsv.parse_name_value('inet:test=("word1 word2", word3)')
        assert (name, value) == ('inet:test', ('word1 word2', 'word3'))

        name, value = qsv.parse_name_value('inet:test=(word1\\,word2, word3)')
        assert (name, value) == ('inet:test', ('word1,word2', 'word3'))

        name, value = qsv.parse_name_value('inet:test=("word1,word2", word3)')
        assert (name, value) == ('inet:test', ('word1,word2', 'word3'))

        name, value = qsv.parse_name_value('inet:test=(\'word1,word2\', word3)')
        assert (name, value) == ('inet:test', ('word1,word2', 'word3'))

        name, value = qsv.parse_name_value('inet:test=(\'word1,word2\', word3)')
        assert (name, value) == ('inet:test', ('word1,word2', 'word3'))

    def test_parse_name_value_compound_integer(self):
        """Test a tuple form compound value"""
        name, value = qsv.parse_name_value('inet:test=(a, 1)')
        assert (name, value) == ('inet:test', ('a', 1))

        name, value = qsv.parse_name_value('inet:test=(1, "a")')
        assert (name, value) == ('inet:test', (1, "a"))

        name, value = qsv.parse_name_value('inet:test=(\'1\', a)')
        assert (name, value) == ('inet:test', ('1', 'a'))

        name, value = qsv.parse_name_value('inet:test=("1", a)')
        assert (name, value) == ('inet:test', ('1', 'a'))


    def test_parse_name_value_compound_recursive(self):
        """"Test recursive parsing tuples"""
        name, value = qsv.parse_name_value('inet:test=((a, b), c)')
        assert (name, value) == ('inet:test', (('a', 'b'),'c'))

        name, value = qsv.parse_name_value('inet:test=(a,(b, c)')
        assert (name, value) == ('inet:test', ('a', ('b','c')))

        name, value = qsv.parse_name_value('inet:test=((a,b), (c, d)')
        assert (name, value) == ('inet:test', (('a', 'b'), ('c', 'd')))

        name, value = qsv.parse_name_value('inet:test=((\'a\',\'b\'), ("c", "d")')
        assert (name, value) == ('inet:test', (('a', 'b'), ('c', 'd')))

    def test_parse_name_value_str_not_compound(self):
        name, value = qsv.parse_name_value('inet:test=(word1)')
        assert (name, value) == ('inet:test', '(word1)')

    def test_parse_name_value_quoted(self):
        name, value = qsv.parse_name_value('it:dev:str="hello (world)"')
        assert (name, value) == ('it:dev:str', 'hello (world)')

    def test_parse_name_value_escaping_quotes(self):
        name, value = qsv.parse_name_value('it:dev:str="hello \"world\""')
        assert (name, value) == ('it:dev:str', 'hello "world"')

    def test_parse_name_value_escaping_quotes(self):
        name, value = qsv.parse_name_value('it:dev:str = \ttab space')
        assert (name, value) == ('it:dev:str', ' \ttab space')

    def test_parse_name_value_invalid(self):
        with pytest.raises(errors.ParameterError):
            qsv.parse_name_value('abc:n')

    def test_whois_recns(self):
        name, value = qsv.parse_name_value('inet:whois:recns=(ns1.google.com, www.example.com=2018-02-06T00:00:00Z)')
        assert (name, value) == ('inet:whois:recns', ('ns1.google.com', ('www.example.com', '2018-02-06T00:00:00Z')))
