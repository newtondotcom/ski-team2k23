
        #`${PUBLIC_CAS_URL}/serviceValidate?ticket=${ticket}&service=${url.origin}/loginCAS`
        #request.headers['Origin']
        url= settings.CAS_SERVER_URL + '/serviceValidate?ticket=' + request.GET['ticket'] + '&service=' + 'http://127.0.0.1:8000' + '/accounts/login/'
        import requests
        res = requests.get(url)
        print(url)
        print(res.text)