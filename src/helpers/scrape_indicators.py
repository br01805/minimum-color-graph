import urllib
import tornado.httpclient as client
import tornado.escape as escape
from libs.config import get_config
from libs.userctx import UserContext
import helpers.http_errors as errors
from http import HTTPStatus

class ScraperServiceError(errors.HttpError):
    """This class reports an HTTP error while trying to scrape indicators."""
    def __init__(self, name, err: Exception):
        """Constructor to create new HTTP error object
        Parameters:
          name  The FQDN endpoint name
          err   The original exception throw by HTTPClient (connectivity, IOError)
        """
        super().__init__(HTTPStatus.SERVICE_UNAVAILABLE, 'scraper_service_problem', -720)
        self.name = name
        self.err = err

    def __str__(self):
        return 'Scraper service error: {}: {}'.format(self.name, self.err)

async def scrape_indicators(logger, text, http_client=None, userctx: UserContext = None):
    """Invoke the scraping service to parse a set of text indicators

      Args:
          text a space: A space separated list of text indicators such as IP address, FQDN, hashes…
          http_client: An optionally specified HTTP client that conforms to Tornado client API
          parent_req_headers: a dictionary of headers name/value pairs, but looking for
              X-User and X-TransactionID to pass to scraper service
    """
    indicators = []
    mock = 1
    if not http_client:
        mock = None
        http_client = client.AsyncHTTPClient()

    if not text:
        raise errors.ParameterError(('text'), 'Missing indicator text field', -700)
    if not isinstance(text, str):
        raise errors.ParameterError(('text'), 'Wrong variable type', -710)
    url = '%s/src/v1/scrape/text/%s' % (get_config('scraper'), urllib.parse.quote(text, safe=''))
    logger.debug('Scraping indicators: %s', url)
    try:
        if not mock:
            resp = await http_client.fetch(url, headers=userctx.get_headers() if userctx else {})
        else:
            resp = http_client.fetch(url, headers=userctx.get_headers() if userctx else {})
    except Exception as err:
        raise ScraperServiceError(get_config('scraper'), err)

    json_data = escape.json_decode(resp.body)

    if not {'status', 'data', 'code'} <= json_data.keys():
        raise ScraperServiceError(get_config('scraper'), Exception('Missing property names'))

    if json_data['status'] == 'success':
        for item in json_data['data']:
            indicators.append({
                'type': item['type'],
                'property': item['property'],
            })
    return indicators
