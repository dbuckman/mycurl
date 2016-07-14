from distutils.core import setup
setup(
  name = 'mycurl',
  packages = ['mycurl'],
  version = '0.1.3',
  description = 'A pycurl wrapper that tries to make pycurl work like requests',
  author = 'Drew Buckman',
  author_email = 'drew.buckman@gmail.com',
  url = 'https://github.com/dbuckman/mycurl',
  download_url = 'https://github.com/dbuckman/mycurl/tarball/0.1.3',
  keywords = ['MycURL', 'cURL', 'HTTP'],
  classifiers = [],
  INSTALL_REQUIRES = [
      'pycurl>=7.43.0',
      'urllib3>=1.16',
      'urlparse2>=1.1.1'
  ]
)
