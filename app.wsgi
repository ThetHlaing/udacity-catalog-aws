import sys, os
sys.path.insert (0,'/var/www/html/catalog')
os.chdir("/var/www/html/catalog")
from application import app as application