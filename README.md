MycURL - PycURL for requests users
===

The goal of MycURL is to be a wrapper for PycURL and make it feel like python Requests.  Requests is a great module and 99.9% of people should use Requests instead of MycURL or use pycurl.  For the 0.1% that want to use MycURL please read on.

## Installation
```python
pip install mycurl
```

## Make a request
To make a request start by importing the module
```python
>>> import mycurl
```
Now, lets get a webpage.  This is the Bluemix status page.
```python
>>> m = mycurl.get('https://status.ng.bluemix.net/')
```
Now m is a Response object.  m has all the info about this request.

MycURL tries to duplicate the requests API.  Not all fuctions have been implemented yet, but MycURL can do lots of good things.

```python
>>> m = mycurl.put('http://httpbin.org/put', data = {'key':'value'})
>>> m = mycurl.delete('http://httpbin.org/delete')
>>> m = mycurl.head('http://httpbin.org/get')
>>> m = mycurl.options('http://httpbin.org/get')
```
## Passing Parameters In URLs
Sometimes you need to pass paramets in the URL.  You can include them in the URL, or just like request you can build a key:value dictionary.
```python
>>> payload = {'key1': 'value1', 'key2': 'value2'}
>>> m = mycurl.get('http://httpbin.org/get', params=payload)
```
You can then view the encoded URL by looking at the m Response object
```python
>>> print(m.url)
http://httpbin.org/get?key2=value2&key1=value1
```
Just like requests any key with a value of `None` will not be included in the URL.

You can also pass a list of items as values.
```python
>>> payload = {'key1': 'value1', 'key2': ['value2', 'value3']}
>>> m = mycurl.get('http://httpbin.org/get', params=payload)
>>> print(m.url)
http://httpbin.org/get?key2=value2&key2=value3&key1=value1
```

## Response Content
Now lets look at the content of a response.  Lets get github's event list.
```python
>>> m = mycurl.get('https://api.github.com/events')
>>> m.text
u'[\n  {\n    "id": "4272705832",\n    "type": "PushEvent",\n    "actor": {\n      "id": 18629836,\n      "login": "floriantoenjes",\n      "display_login": "floriantoenjes",\n      "gravatar_id": "",\n      "url": "https://api.github.com/...
```
MycURL will try and automatically decode content.  `More work and testing is needed here`
```python
>>> m.encoding
'iso-8859-1'
```

## Binary Response Content
`More work and testing is needed here`
m.content will give a resonse now but is not in Binary form

## JSON Response Content
There is also a builtin JSON decoder, just like requests
```python
>>> m = mycurl.get('https://api.github.com/events')
>>> m.json()
[{u'payload': {u'size': 1, u'head': u'63488dea29f8e8c31b1bf7db7b6c18d7a5f0b50a', u'commits': [{u'distinct': True, u'sha': u'63488dea29f8e8c31b1bf7db7b6c18d7a5f0b50a', u'message': u'build', u'url':...
```
In case the JSON decoding fails, r.json raises an exception.

## Custom Headers
If you want to use custom headers just pass in a dict.

```python
>>> headers = {'user-agent': 'my-app/0.0.1'}
>>> m = mycurl.get('http://httpbin.org/get', headers=headers)
```
Note: Like requests Authorization headers set with headers= will be overridden if credentials are specified with auth=

## POST requests
When you want to send form-encoded date pass a dictionary to the data argument.  The dictionary of data will automatically be form-encoded when the request is made.

```python
>>> payload = {'key1': 'value1', 'key2': 'value2'}
>>> m = mycurl.post("http://httpbin.org/post", data=payload)
>>> print(m.text)
{
... 
  "form": {
    "key1": "value1", 
    "key2": "value2"
  }, 
 ...
}
```

## POST a Multipart-Encoded File
It is simple to upload Multipart-encoded files.
```python
>>> files = {'file': open('file.txt', 'rb')}
>>> m = mycurl.post('http://httpbin.org/post', files=files
... )
>>> m = mycurl.post('http://httpbin.org/post', files=files)
>>> print(m.text)
{
...
  "files": {
    "file": "This is a file\n"
  }, 
...
}
```
You can set the filename, content_type and headers explicitly:

## Response Status Codes
```python
>>> m.status_code
200
```

## Response Headers
Response headers as python a dict
```python
>>> m = mycurl.get('http://httpbin.org/get')
>>> m.headers
{u'content-length': u'468', u'age': u'0', u'cache-control': u'proxy-revalidate', u'server': u'nginx', u'connection': u'Keep-Alive', u'access-control-allow-credentials': u'true', u'date': u'Wed, 13 Jul 2016 18:33:24 GMT', u'access-control-allow-origin': u'*', u'content-type': u'application/json'}
>>>
>>> m.headers['server']
u'nginx'
```

# Redirection and History
MycURL redirect works just like requests.  Redirects will be performed on all verbs except HEAD.

You can then use the Response.history to get a list of Response objects.
```python
>>> m = mycurl.get('http://github.com')
>>> m.url
u'https://github.com/'
>>> m.status_code
200
>>> m.history
[<Response [301]>]
>>> m.history[0].url
u'http://github.com/'
```
If you would like to not follow redirects, you can do that too.
```python
>>> m = mycurl.get('http://github.com', allow_redirects=False)
>>> m.status_code
301
>>> m.history
[]
```
## Timeouts
The timeout argument implements the libcurl CONNECTTIMEOUT method and works like requests timeout.  Give the timeout argument the number of seconds
```python
>>> m = mycurl.get('http://github.com', timeout=0.001)
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
  File "mycurl/methods.py", line 573, in get
    return request('get', url, params=params, **kwargs)
  File "mycurl/methods.py", line 518, in request
    handelError(e)
  File "mycurl/methods.py", line 373, in handelError
    raise ConnectionError(error[1])
mycurl.exceptions.ConnectionError: Resolving timed out after 7 milliseconds
```
With MycURL you can also set the maximum time the request is allowed to take using the maxtime argument.  This implements the libcurl TIMEOUT option.  `This is not supported by requests`
```python
>>> m = mycurl.get('http://github.com', maxtime=1)
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
  File "mycurl/methods.py", line 573, in get
    return request('get', url, params=params, **kwargs)
  File "mycurl/methods.py", line 518, in request
    handelError(e)
  File "mycurl/methods.py", line 373, in handelError
    raise ConnectionError(error[1])
mycurl.exceptions.ConnectionError: Resolving timed out after 1541 milliseconds
>>> m = mycurl.get('http://github.com', maxtime=2)
```

## cURL info/performance data
`Not supported by requests`

This implement the curl_easy_getinfo() method
```python
>>> m = mycurl.get('http://github.com')
>>> m.info
{'SPEED_UPLOAD': 0.0, 'SSL_VERIFYRESULT': 0, 'HTTPAUTH_AVAIL': 0, 'HEADER_SIZE': 2310, 'TIME_REDIRECT': 0.0, 'EFFECTIVE_URL': 'https://github.com/', 'CONTENT_LENGTH_UPLOAD': -1.0, 'REDIRECT_URL': None, 'TIME_APPCONNECT': 0.260827, 'TIME_CONNECT': 0.159748, 'PRIMARY_IP': '192.30.253.113', 'SIZE_UPLOAD': 0.0, 'REDIRECT_COUNT': 0, 'SIZE_DOWNLOAD': 7570.0, 'CURLINFO_LASTSOCKET': 3, 'PROXYAUTH_AVAIL': 0, 'HTTP_CODE': 200, 'SPEED_DOWNLOAD': 20503.0, 'LOCAL_IP': '10.0.2.15', 'CONTENT_LENGTH_DOWNLOAD': -1.0, 'TIME_TOTAL': 0.369197, 'TIME_PRETRANSFER': 0.260931, 'OS_ERRNO': 0, 'HTTP_CONNECTCODE': 0, 'RESPONSE_CODE': 200, 'REQUEST_SIZE': 193, 'NUM_CONNECTS': 1, 'SSL_ENGINES': [], 'PRIMARY_PORT': 443, 'CONTENT_TYPE': 'text/html; charset=utf-8', 'TIME_STARTTRANSFER': 0.335013, 'TIME_NAMELOOKUP': 0.130823, 'INFO_COOKIELIST': []}

```


## Not implemented yet
`m.raw`

`need to implement post json arg`

`need to work on post file options, and string as file`

`m.headers.get()`

`Cookies`

`Session`

`m.raise_for_status() needs work`

