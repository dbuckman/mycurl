import sys, os, pycurl, re, collections, datetime, urllib3
import json as js
from cStringIO import StringIO
from urllib import quote
from urlparse import urlparse
from urlparse2 import urlunparse
from .exceptions import ConnectionError, InvalidURL, HTTPError

"""
TODO:
Bugs
-

Response Object
-m.raise_for_status()
-m.cookies['example_cookie_name']
-m.content needs to be bytestring
-Raw Response Content

Requests
-need auth option to override Authorization header
-?requests.codes.ok

Errors and Exceptions

Session Objects
c.FORM_CONTENTTYPE
Custom Authentication
Proxies

"""

try:
    # python 3
    from urllib.parse import urlencode
except ImportError:
    # python 2
    from urllib import urlencode

# Syntax sugar.
_ver = sys.version_info

#: Python 2.x?
is_py2 = (_ver[0] == 2)

#: Python 3.x?
is_py3 = (_ver[0] == 3)

# The unreserved URI characters (RFC 3986)
UNRESERVED_SET = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    + "0123456789-._~")

resp_headers = {}

CURL_INFO_MAP = {
    # timers
    # An overview of the six time values available from curl_easy_getinfo()
    # perform() --> NAMELOOKUP --> CONNECT --> APPCONNECT
    # --> PRETRANSFER --> STARTTRANSFER --> TOTAL --> REDIRECT
    "TOTAL_TIME": pycurl.TOTAL_TIME,
    "NAMELOOKUP_TIME": pycurl.NAMELOOKUP_TIME,
    "CONNECT_TIME": pycurl.CONNECT_TIME,
    "APPCONNECT_TIME": pycurl.APPCONNECT_TIME,
    "PRETRANSFER_TIME": pycurl.PRETRANSFER_TIME,
    "STARTTRANSFER_TIME": pycurl.STARTTRANSFER_TIME,
    "REDIRECT_TIME": pycurl.REDIRECT_TIME,
    "HTTP_CODE": pycurl.HTTP_CODE,
    "REDIRECT_COUNT": pycurl.REDIRECT_COUNT,
    "REDIRECT_URL": pycurl.REDIRECT_URL,
    "SIZE_UPLOAD": pycurl.SIZE_UPLOAD,
    "SIZE_DOWNLOAD": pycurl.SIZE_DOWNLOAD,
    "SPEED_DOWNLOAD": pycurl.SPEED_DOWNLOAD,
    "SPEED_UPLOAD": pycurl.SPEED_UPLOAD,
    "HEADER_SIZE": pycurl.HEADER_SIZE,
    "REQUEST_SIZE": pycurl.REQUEST_SIZE,
    "SSL_VERIFYRESULT": pycurl.SSL_VERIFYRESULT,
    "SSL_ENGINES": pycurl.SSL_ENGINES,
    "CONTENT_LENGTH_DOWNLOAD": pycurl.CONTENT_LENGTH_DOWNLOAD,
    "CONTENT_LENGTH_UPLOAD": pycurl.CONTENT_LENGTH_UPLOAD,
    "CONTENT_TYPE": pycurl.CONTENT_TYPE,

    "HTTPAUTH_AVAIL": pycurl.HTTPAUTH_AVAIL,
    "PROXYAUTH_AVAIL": pycurl.PROXYAUTH_AVAIL,
    "OS_ERRNO": pycurl.OS_ERRNO,
    "NUM_CONNECTS": pycurl.NUM_CONNECTS,
    "PRIMARY_IP": pycurl.PRIMARY_IP,
    "CURLINFO_LASTSOCKET": pycurl.LASTSOCKET,
    "EFFECTIVE_URL": pycurl.EFFECTIVE_URL,
    "INFO_COOKIELIST": pycurl.INFO_COOKIELIST,
    "RESPONSE_CODE": pycurl.RESPONSE_CODE,
    "HTTP_CONNECTCODE": pycurl.HTTP_CONNECTCODE,
    "LOCAL_IP": pycurl.LOCAL_IP,
    "PRIMARY_PORT": pycurl.PRIMARY_PORT,
    }

class Response(object):
  __attrs__ = [
        'content', 'status_code', 'headers', 'url', 'history',
        'encoding', 'reason', 'cookies', 'elapsed', 'request', 'info'
    ]
  
  def __init__(self, **kwargs):
    super(Response, self).__init__()

    self.history     = []
    self.url         = None
    self.text        = None
    self.content     = None
    self.status_code = None
    self.headers     = {}
    self.encoding    = None
    self.info        = {}
    self.elapsed     = datetime.timedelta(0)

  def __getstate__(self):
    # Consume everything; accessing the content attribute makes
    # sure the content has been fully read.
    if not self._content_consumed:
      self.content

    return dict(
      (attr, getattr(self, attr, None))
        for attr in self.__attrs__
    )

  def __setstate__(self, state):
    for name, value in state.items():
      setattr(self, name, value)

    # pickled objects do not have .raw
    setattr(self, '_content_consumed', True)
    setattr(self, 'raw', None)

  def __repr__(self):
    return '<Response [%s]>' % (self.status_code)

  def __bool__(self):
    """Returns true if :attr:`status_code` is 'OK'."""
    return self.ok

  def __nonzero__(self):
    """Returns true if :attr:`status_code` is 'OK'."""
    return self.ok

  #def __iter__(self):
    #"""Allows you to use a response as an iterator."""
    #return self.iter_content(128)

  @property
  def ok(self):
    try:
      self.raise_for_status()
    except HTTPError:
      return False
    return True
    
  def json(self):
    text = self.text
    return js.loads(text)

  def raise_for_status(self):
    """Raises stored :class:`HTTPError`, if one occurred."""

    http_error_msg = ''

    if 400 <= self.status_code < 500:
      http_error_msg = '%s Client Error: %s for url: %s' % (self.status_code, self.reason, self.url)

    elif 500 <= self.status_code < 600:
      http_error_msg = '%s Server Error: %s for url: %s' % (self.status_code, self.reason, self.url)

    if http_error_msg:
      raise HTTPError(http_error_msg, response=self)



##########
#utilities
def to_native_string(string, encoding='ascii'):
    """
    Given a string object, regardless of type, returns a representation of that
    string in the native string type, encoding and decoding where necessary.
    This assumes ASCII unless told otherwise.
    """
    if isinstance(string, builtin_str):
        out = string
    else:
        if is_py2:
            out = string.encode(encoding)
        else:
            out = string.decode(encoding)

    return out

def unquote_unreserved(uri):
    """Un-escape any percent-escape sequences in a URI that are unreserved
    characters. This leaves all reserved, illegal and non-ASCII bytes encoded.
    """
    parts = uri.split('%')
    for i in range(1, len(parts)):
        h = parts[i][0:2]
        if len(h) == 2 and h.isalnum():
            try:
                c = chr(int(h, 16))
            except ValueError:
                raise InvalidURL("Invalid percent-escape sequence: '%s'" % h)

            if c in UNRESERVED_SET:
                parts[i] = c + parts[i][2:]
            else:
                parts[i] = '%' + parts[i]
        else:
            parts[i] = '%' + parts[i]
    return ''.join(parts)

def requote_uri(uri):
    """Re-quote the given URI.
    This function passes the given URI through an unquote/quote cycle to
    ensure that it is fully and consistently quoted.
    """
    safe_with_percent = "!#$%&'()*+,/:;=?@[]~"
    safe_without_percent = "!#$&'()*+,/:;=?@[]~"
    try:
        # Unquote only the unreserved characters
        # Then quote only illegal characters (do not quote reserved,
        # unreserved, or '%')
        return quote(unquote_unreserved(uri), safe=safe_with_percent)
    except InvalidURL:
        # We couldn't unquote the given URI, so let's try quoting it, but
        # there may be unquoted '%'s in the URI. We need to make sure they're
        # properly quoted so they do not cause issues elsewhere.
        return quote(uri, safe=safe_without_percent)
    
def prepare_url(url, params):
  """Prepares the given HTTP URL."""
  #: Accept objects that have string representations.
  #: We're unable to blindly call unicode/str functions
  #: as this will include the bytestring indicator (b'')
  #: on python 3.x.
  #: https://github.com/kennethreitz/requests/pull/2238
  if isinstance(url, bytes):
    url = url.decode('utf8')
  else:
    url = unicode(url) if is_py2 else str(url)

  # Don't do any URL preparation for non-HTTP schemes like `mailto`,
  # `data` etc to work around exceptions from `url_parse`, which
  # handles RFC 3986 only.
  if ':' in url and not url.lower().startswith('http'):
    return url

  # Support for unicode domain names and paths.
  try:
    scheme, auth, host, port, path, query, fragment = urllib3.util.url.parse_url(url)
  except LocationParseError as e:
    raise InvalidURL(*e.args)

  if not scheme:
    error = ("Invalid URL {0!r}: No schema supplied. Perhaps you meant http://{0}?")
    error = error.format(to_native_string(url, 'utf8'))

    raise MissingSchema(error)

  if not host:
    raise InvalidURL("Invalid URL %r: No host supplied" % url)

  # Only want to apply IDNA to the hostname
  try:
    host = host.encode('idna').decode('utf-8')
  except UnicodeError:
    raise InvalidURL('URL has an invalid label.')        
        
  # Carefully reconstruct the network location
  netloc = auth or ''
  if netloc:
    netloc += '@'
  netloc += host
  if port:
    netloc += ':' + str(port)

  # Bare domains aren't valid URLs.
  if not path:
    path = '/'

  if is_py2:
    if isinstance(scheme, str):
      scheme = scheme.encode('utf-8')
    if isinstance(netloc, str):
      netloc = netloc.encode('utf-8')
    if isinstance(path, str):
      path = path.encode('utf-8')
    if isinstance(query, str):
      query = query.encode('utf-8')
    if isinstance(fragment, str):
      fragment = fragment.encode('utf-8')

  if isinstance(params, (str, bytes)):
    params = to_native_string(params)

  enc_params = encode_params(params)
  if enc_params:
    if query:
      query = '%s&%s' % (query, enc_params)
    else:
      query = enc_params

  url = requote_uri(urlunparse([scheme, netloc, path, None, query, fragment]))
  return url

def to_key_val_list(value):
    """Take an object and test to see if it can be represented as a
    dictionary. If it can be, return a list of tuples, e.g.,
    ::
        >>> to_key_val_list([('key', 'val')])
        [('key', 'val')]
        >>> to_key_val_list({'key': 'val'})
        [('key', 'val')]
        >>> to_key_val_list('string')
        ValueError: cannot encode objects that are not 2-tuples.
    """
    if value is None:
        return None

    if isinstance(value, (str, bytes, bool, int)):
        raise ValueError('cannot encode objects that are not 2-tuples')

    if isinstance(value, collections.Mapping):
        value = value.items()

    return list(value)

def encode_params(data):
  if isinstance(data, (str, bytes)):
    return data
  elif hasattr(data, 'read'):
    return data
  elif hasattr(data, '__iter__'):
    result = []
    for k, vs in to_key_val_list(data):
      if isinstance(vs, basestring) or not hasattr(vs, '__iter__'):
        vs = [vs]
      for v in vs:
        if v is not None:
          result.append(
            (k.encode('utf-8') if isinstance(k, str) else k,
             v.encode('utf-8') if isinstance(v, str) else v))
    return urlencode(result, doseq=True)
  else:
    return data

def header_function(header_line):
  header_line = header_line.decode('iso-8859-1')
  if ':' not in header_line:
    return
  name, value = header_line.split(':', 1)
  name = name.strip()
  value = value.strip()
  name = name.lower()
  resp_headers[name] = value


def handelError(error):
  if error[0] == 0:
    pass
  elif error[0] == 1:
    raise InvalidSchema(error[1])
  elif error[0] == 3:
    raise InvalidURL(error[1])
  elif error[0] == 5:
    raise ProxyError(error[1])
  else:
    raise ConnectionError(error[1])


def get_info(curl_obj):
  info = {}
  for field, value in CURL_INFO_MAP.iteritems():
    try:
      field_data = curl_obj.getinfo(value)
    except Exception, e:
      #logger.warn(e)
      continue
    else:
      if "_TIME" in field:
        field_x = field.split("_")
        field = "TIME_" + field_x[0]
        info[field] = field_data
      else:
        info[field] = field_data
  return info

def redirect_url(scheme, netloc, url):
  parsed_url = urlparse(url)

  # Handle redirection without scheme (see: RFC 1808 Section 4)
  if url.startswith('//'):
    url = scheme + url

  # Facilitate relative 'location' headers, as allowed by RFC 7231.
  # (e.g. '/path/to/resource' instead of 'http://domain.tld/path/to/resource')
  # Compliant with RFC3986, we percent encode the url.
  if not parsed_url.netloc:
    url = scheme + "://" + netloc + url

  return url
  
#utilities
##########

def request(method, url, **kwargs):
  parsed_url = urlparse(url)
  scheme = parsed_url.scheme
  netloc = parsed_url.netloc
  
  runverb = True
  thisHistory = []
  while runverb == True:
    if kwargs['allow_redirects'] == False:
      runverb = False
    #print "here1"
    #setup a buffer to hold pycurl data and creat a pycurl instance
    buffer = StringIO()
    c = pycurl.Curl()

    c.setopt(c.ACCEPT_ENCODING, "")
    
    if kwargs['verbose'] == True:
      c.setopt(c.VERBOSE, True)

    if kwargs['verify'] == False:
      c.setopt(c.SSL_VERIFYHOST, 0)
      c.setopt(c.SSL_VERIFYPEER, 0)

    if kwargs['timeout'] != None:
      timeout = int(kwargs['timeout'] * 1000)
      c.setopt(pycurl.CONNECTTIMEOUT_MS, timeout)
    if kwargs['maxtime'] != None:
      maxtime = int(kwargs['maxtime'] * 1000)
      c.setopt(pycurl.TIMEOUT_MS, maxtime)

    url = prepare_url(url, kwargs['params'])
    c.setopt(c.URL, url)

    #check if we need to authenticate
    hasAuth = False
    if kwargs['auth'] != None and type(kwargs['auth']) is tuple:
      hasAuth = True
      auth = kwargs['auth']
      c.setopt(c.USERNAME, auth[0])
      c.setopt(c.PASSWORD, auth[1])
      
    #check if we need to set header options
    if kwargs['headers'] != None and type(kwargs['headers']) is dict:
      cheaders = []
      for header in kwargs['headers']:
        if hasAuth == True and header.lower() == 'authorization':
          pass
        else:
          #cheaders.append(header.lower() + ": " + headers[header.lower()])
          cheaders.append(header + ": " + kwargs['headers'][header])
      c.setopt(c.HTTPHEADER, cheaders)


    if method == "post":
      c.setopt(pycurl.POST, 1)
    elif method == "put":
      c.setopt(pycurl.CUSTOMREQUEST, "PUT")
    elif method == "patch":
      c.setopt(pycurl.CUSTOMREQUEST, "PATCH")
    elif method == "delete":
      c.setopt(pycurl.CUSTOMREQUEST, "DELETE")
    elif method == "options":
      c.setopt(pycurl.CUSTOMREQUEST, "OPTIONS")
    elif method == "head":
      c.setopt(pycurl.NOBODY, 1)
      #print "set head"
      
    if method == "post" or method == "put":
      #check if we have files to post
      #if we have files we will post all the files and data with HTTPPOST
      #else check if we have data and do a normal post
      post_data = []
      httppost = False
      if kwargs['files'] != None:
        httppost = True
        filesize = 0
        for f in kwargs['files']:
          if type(kwargs['files'][f]) is str:
            filesize += os.path.getsize(kwargs['files'][f])
            post_data.append((f, (c.FORM_FILE, kwargs['files'][f])))
            #c.setopt(pycurl.HTTPPOST, [(f, (c.FORM_FILE, files[f]))])
          elif type(kwargs['files'][f]) is file:
            filesize += os.path.getsize(kwargs['files'][f].name)
            post_data.append((f, (c.FORM_FILE, kwargs['files'][f].name)))
            #c.setopt(pycurl.HTTPPOST, [(f, (c.FORM_FILE, files[f].name))])
          elif type(kwargs['files'][f]) is tuple:
            pass #need to work on this one
        c.setopt(pycurl.INFILESIZE, filesize)
        if kwargs['data'] != None:
          for key, value in kwargs['data'].iteritems():
            temp = [key,value]
            post_data.append(tuple(temp))
        c.setopt(c.HTTPPOST, post_data)
        kwargs['data'] = None

      if kwargs['data'] != None:
        encoded_post_data = encode_params(kwargs['data'])
        c.setopt(c.POSTFIELDS, encoded_post_data)

    #print "here2"
    c.setopt(c.WRITEDATA, buffer)
    c.setopt(c.HEADERFUNCTION, header_function)
    #print "here3"
    try:
      c.perform()
    except pycurl.error, e:
      handelError(e)
    #print "here4"

    body = buffer.getvalue()
    status_code=c.getinfo(pycurl.HTTP_CODE)
    info = get_info(c)
    c.close()
    #print "here5"
    # Figure out what encoding was sent with the response, if any.
    # Check against lowercased header name.
    encoding = None
    if 'content-type' in resp_headers:
      content_type = resp_headers['content-type'].lower()
      match = re.search('charset=(S+)', content_type)
      if match:
        encoding = match.group(1)
    if encoding is None:
      # Default encoding for HTML is iso-8859-1.
      # Other content types may have different default encoding,
      # or in case of binary data, may have no encoding at all.
      encoding = 'iso-8859-1'
    #print "here6"
    elapsed = datetime.timedelta(seconds=info["TIME_TOTAL"])

    response = Response()
    response.url = url

    response.text = body.decode(encoding, 'strict')
    response.content = body
    response.status_code = status_code
    response.headers = resp_headers
    response.encoding = encoding
    response.info = info
    response.elapsed = elapsed
    
    if int(response.status_code) >= 300 and int(response.status_code) < 400 and runverb == True:
      thisHistory.append(response)
      response.history = thisHistory
      url = response.headers['location']
      url = redirect_url(scheme, netloc, url)
    else:
      response.history = thisHistory
      runverb = False

  return response


def get(url, params=None, **kwargs):
  kwargs.setdefault('allow_redirects', True)
  kwargs.setdefault('headers', None)
  kwargs.setdefault('auth', None)
  kwargs.setdefault('timeout', None)
  kwargs.setdefault('maxtime', None)
  kwargs.setdefault('verbose', False)
  kwargs.setdefault('verify', True)
  return request('get', url, params=params, **kwargs)


def head(url, params=None, **kwargs):
  kwargs.setdefault('allow_redirects', False)
  kwargs.setdefault('headers', None)
  kwargs.setdefault('auth', None)
  kwargs.setdefault('timeout', None)
  kwargs.setdefault('maxtime', None)
  kwargs.setdefault('verbose', False)
  kwargs.setdefault('verify', True)
  return request('head', url, params=params, **kwargs)


def post(url, params=None, **kwargs):
  kwargs.setdefault('allow_redirects', True)
  kwargs.setdefault('headers', None)
  kwargs.setdefault('auth', None)
  kwargs.setdefault('timeout', None)
  kwargs.setdefault('maxtime', None)
  kwargs.setdefault('verbose', False)
  kwargs.setdefault('verify', True)
  kwargs.setdefault('data', None)
  kwargs.setdefault('files', None)
  return request('post', url, params=params, **kwargs)


def put(url, params=None, **kwargs):
  kwargs.setdefault('allow_redirects', True)
  kwargs.setdefault('headers', None)
  kwargs.setdefault('auth', None)
  kwargs.setdefault('timeout', None)
  kwargs.setdefault('maxtime', None)
  kwargs.setdefault('verbose', False)
  kwargs.setdefault('verify', True)
  kwargs.setdefault('data', None)
  kwargs.setdefault('files', None)
  return request('put', url, params=params, **kwargs)


def patch(url, params=None, **kwargs):
  kwargs.setdefault('allow_redirects', True)
  kwargs.setdefault('headers', None)
  kwargs.setdefault('auth', None)
  kwargs.setdefault('timeout', None)
  kwargs.setdefault('maxtime', None)
  kwargs.setdefault('verbose', False)
  kwargs.setdefault('verify', True)
  kwargs.setdefault('data', None)
  kwargs.setdefault('files', None)
  return request('patch', url, params=params, **kwargs)


def delete(url, params=None, **kwargs):
  kwargs.setdefault('allow_redirects', True)
  kwargs.setdefault('headers', None)
  kwargs.setdefault('auth', None)
  kwargs.setdefault('timeout', None)
  kwargs.setdefault('maxtime', None)
  kwargs.setdefault('verbose', False)
  kwargs.setdefault('verify', True)
  kwargs.setdefault('data', None)
  kwargs.setdefault('files', None)
  return request('delete', url, params=params, **kwargs)


def options(url, params=None, **kwargs):
  kwargs.setdefault('allow_redirects', True)
  kwargs.setdefault('headers', None)
  kwargs.setdefault('auth', None)
  kwargs.setdefault('timeout', None)
  kwargs.setdefault('maxtime', None)
  kwargs.setdefault('verbose', False)
  kwargs.setdefault('verify', True)
  return request('options', url, params=params, **kwargs)

