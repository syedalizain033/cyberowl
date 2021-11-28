import os

class WebAttacks:
    def sql(url):
        localurl=url
        command="sqlmap -u {0} --dbs".format(localurl)
        os.system(command)
        