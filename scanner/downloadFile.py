from django.http import HttpResponse
import mimetypes
class Downloader:
    def downloadWayBackFile():
        filepath='/home/capt/FYP/v1/cyberowl/waybackurls.txt'
        filename='waybackurls'

        fl=open(filepath, 'r')
        mime_type, _= mimetypes.guess_type(filepath)
        response=HttpResponse(fl, content_type=mime_type)
        response['Content-Disposition']="attachment; filename=%s" % filename
        return response