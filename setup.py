from distutils.core import setup
setup(
  name = 'mycurl',
  packages = ['mycurl'],
  version = '0.1.5',
  description = 'A pycurl wrapper that tries to make pycurl work like requests',
  author = 'Drew Buckman',
  author_email = 'drew.buckman@gmail.com',
  url = 'https://github.com/dbuckman/mycurl',
  download_url = 'https://github.com/dbuckman/mycurl/tarball/0.1.5',
  keywords = ['MycURL', 'cURL', 'HTTP'],
  classifiers = [],
  install_requires = ['pycurl','urllib3','urlparse2']
)
