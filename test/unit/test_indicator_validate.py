from helpers.indicator_validate import IndicatorValidate

class TestIndicatorValidate:

    def test_md5(self):
        the_matcher = IndicatorValidate()
        assert the_matcher.is_md5('ef99152d3da4a480167ce997b37ce813')

    def test_sha1(self):
        the_matcher = IndicatorValidate()
        assert the_matcher.is_sha1('BD2F1D59F162D5A75586800BE1CCD53457932BCF')

    def test_sha256(self):
        the_matcher = IndicatorValidate()
        assert the_matcher.is_sha256(
            'FE77B95834807B9AB12FCC6D997691D1BC011FC7E912D94882FB9560C1AB05D1')

    def test_sha512(self):
        the_matcher = IndicatorValidate()
        assert the_matcher.is_sha512(
            '1b7d6e3ba7143e2834d3dd89105bba3e0ebb46838ba955e4a2a145e422426515d89e6834aedeef46f44b367d65405c52a542ce88afa3066e4586521b09860fb8')

    def test_ip(self):
        the_matcher = IndicatorValidate()
        assert the_matcher.is_ipaddr('9.9.9.9')
        assert the_matcher.is_ipv4('9.9.9.9')
        assert the_matcher.is_ipv6('2001:db8:3:4::192.0.2.33')
        assert the_matcher.is_ipv6('fe80::e985:2178:c137:8a88')
        assert not the_matcher.is_ipv6('2001:db8:3:4::192.0.2,33')

    def test_fqdn(self):
        the_matcher = IndicatorValidate()
        assert the_matcher.is_fqdn('www.example.com')
        assert the_matcher.is_fqdn('WWW.EXAMPLE.COM')
        assert not the_matcher.is_fqdn('www.')
        assert not the_matcher.is_fqdn('www')

        names = ('-hello.com',
                 'hello.-com',
                 '.a',
                 'a.',
                 'a',
                 'aa',
                 )
        for name in names:
            assert not the_matcher.is_fqdn(name)

    def test_telephone(self):
        the_matcher = IndicatorValidate()
        assert the_matcher.is_telephone('1112223333')
        assert the_matcher.is_telephone('111-222-3333')
        assert the_matcher.is_telephone('(111) 222-3333')
        assert the_matcher.is_telephone('(111)222-3333')
        assert the_matcher.is_telephone('(111) 222-3333')

    def test_email(self):
        the_matcher = IndicatorValidate()
        assert the_matcher.is_email('george@example.com')
        assert the_matcher.is_email('george_smith@example.com')
        assert the_matcher.is_email('george.smith@example.com')
        assert the_matcher.is_email('george-smith@example.com')
        assert the_matcher.is_email('ddennerline.W4QFJ1ZRS@ibm-security.com')
        assert not the_matcher.is_email('@example.com')
        assert not the_matcher.is_email('bill@example')
        assert not the_matcher.is_email('01234567890123456789012345678901234567890123456789012345678901234@example.com')
        assert not the_matcher.is_email('bill@example.com<script alert("hello")>')

    def test_url(self):
        the_matcher = IndicatorValidate()
        assert the_matcher.is_url('http://www.example.com/index.html')
        assert the_matcher.is_url('http://www.example.com:8080/index.html')
        assert the_matcher.is_url('http://localhost/index.html')
        assert not the_matcher.is_url('http:/localhost/index.html')
        assert not the_matcher.is_url('http')
        assert not the_matcher.is_url('http://')
        assert not the_matcher.is_url('.')

    def test_form(self):
        forms = [['9.9.9.9', 'inet:ipv4'],
                 ['george@example.com', 'inet:email'],
                 ['www.example.com', 'inet:fqdn'],
                 ['ef99152d3da4a480167ce997b37ce813', 'hash:md5'],
                 ['BD2F1D59F162D5A75586800BE1CCD53457932BCF', 'hash:sha1'],
                 ['FE77B95834807B9AB12FCC6D997691D1BC011FC7E912D94882FB9560C1AB05D1', 'hash:sha256'],
                 ['http://www.example.com/', 'inet:url']]

        for form in forms:
            the_matcher = IndicatorValidate()
            assert the_matcher.match_form(form[0]) == form[1]

    def test_is_syn_form(self):
        the_matcher = IndicatorValidate()

        test_cases = (('inet:ipv4=9.9.9.9', True),
                      ('ipv4=9.9.9.9', False),
                      ('=9.9.9.9', False),
                      ('9.9.9.9', False),
                      )

        for tc in test_cases:
            assert the_matcher.is_syn_form(tc[0]) == tc[1]

    def test_is_syn_value(self):
        the_matcher = IndicatorValidate()

        test_cases = (#('it:dev:regval=("HKEY_LOCAL_MACHINE\\SOFTWARE\\ABC\\The Key, "C:\\Program File\\IBM\\run.exe")', False),
                      ('inet:ipv4=9.9.9.9', True),
                      ('inet:ipv4="9.9.9.9"', True),
                      ('it:dev:str="quote(\\")"', True),
                      ('inet:whois:email=(example.com, badapple@contactme.biz)', True),
                      ('it:dev:str=""', False),
                      ('', False),
                      ('it:dev:str="', False),
                      ('it:dev:str=hello(world)', False),
                      ('it:dev:str=quote(")', False),
                      ('it:dev:regval="*"', True),
                      ('it:dev:regval=*', True),
                      ('it:dev:regval=83ac4984d21d7e8812338944f1b8a3b2', True),
                      ('it:dev:regval=("HKEY_LOCAL_MACHINE\\SOFTWARE\\ABC\\The Key", "C:\\Program File\\IBM\\run.exe")',
                       True),
                      ('it:dev:regval="HKEY_LOCAL_MACHINE\\Bad Key", "C:\\Program File\\IBM\\run.exe")', False),
                      ('it:dev:regval=("HKEY_LOCAL_MACHINE\\Bad Key", "C:\\Program File\\IBM\\run.exe"', False),
                      ('it:dev:regval=(HKEY_LOCAL_MACHINE\\Bad Key", "C:\\Program File\\IBM\\run.exe")', False),
                      ('it:dev:regval=("HKEY_LOCAL_MACHINE\\Bad Key, "C:\\Program File\\IBM\\run.exe")', False),
                      ('it:dev:regval=("HKEY_LOCAL_MACHINE\\Bad Key", C:\\Program File\\IBM\\run.exe")', False),
                      ('it:dev:regval=("HKEY_LOCAL_MACHINE\\Bad Key", "C:\\Program File\\IBM\\run.exe)', False),
                      )
        for tc in test_cases:
            assert the_matcher.is_syn_value(tc[0]) == tc[1], 'Cannot match {}'.format(tc[0])


    def test_is_guids(self):
        the_matcher = IndicatorValidate()
        assert the_matcher.is_syn_guid('185e2db18f01bc9c3cf5288daafde221c919a798c70f8950746312feae1d5c05')
        assert not the_matcher.is_syn_guid('185e2db18f01bc9c3cf5288daafde221c919a798c70f8950746312feae1d5c0')

        assert the_matcher.is_form_guid('guid:b604a5a269e5dab3e8d6d57b0e7509d0')
        assert the_matcher.is_form_guid('e7ffc308789389cdbf5bb4a1b83e4140')
        assert not the_matcher.is_form_guid('e7ffc308789389cdbf5bb4a1b83e414')

    def test_none_value(self):
        the_matcher = IndicatorValidate()
        assert not the_matcher.match_form(None)

    def test_filebytes_value(self):
        the_matcher = IndicatorValidate()
        assert the_matcher.is_filebytes('guid:b604a5a269e5dab3e8d6d57b0e7509d0')
        assert the_matcher.is_filebytes('sha256:FE77B95834807B9AB12FCC6D997691D1BC011FC7E912D94882FB9560C1AB05D1')

        # too short
        assert not the_matcher.is_filebytes('guid:b604a5a269e5dab3e8d6d57b0e7509d')
        assert not the_matcher.is_filebytes('sha256:FE77B95834807B9AB12FCC6D997691D1BC011FC7E912D94882FB9560C1AB05D')

        # too long
        assert not the_matcher.is_filebytes('guid:b604a5a269e5dab3e8d6d57b0e7509d00')
        assert not the_matcher.is_filebytes('sha256:FE77B95834807B9AB12FCC6D997691D1BC011FC7E912D94882FB9560C1AB05D10')

