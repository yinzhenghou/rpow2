from curl_cffi import requests, json

cookie = "_ga=GA1.1.988665284.1778575666; cf_clearance=NMdKEYqykWRBUg1DnwRn2Dea0zIOJz.tHBi5_.tLJNA-1778664035-1.2.1.1-ZFxlZnFsWb220wy4.Q8tpfDvMosQCcotwRU2iBYdoLgxUolPrmsCvqRqJoBIfWLX0J4WTyeT.FWcU.LM2g85wQ0TmFdOk8VPj01gMvCgab8cxGINCziVeyJACuyTOaUP18LkxXCaBUWUiaN4GFN7R6BF6O2MvfoW9H3ZB_OdElgPkAkkDOuBRXEuJPNoRWJ6zZlCsxGR1pUa.R_YDyERk8wbXSG_1kNw08h107HAi04GUNej3VsTOBPKUj3CWGTXlloSrsW4jWK6oAVQZdo1AtxQJzI.w9wct28qTNrfhpcCAxK2u7uhQCTwI.xLuw5ivPGq99mE_YHWSX4sWXvCDQ; _ga_3PG48F0MCP=GS2.1.s1778664035$o4$g0$t1778664035$j60$l0$h0; rpow_session=eyJlbWFpbCI6Imh5ejIwMDI3NkBnbWFpbC5jb20iLCJleHAiOjE3ODEyNTYwNzZ9.gyjKocki_T8fAZYLZnLDHklcc8Myjfsxz7BtbxjrvYk"

s = requests.Session(impersonate="chrome131")
s.headers.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36",
    "Content-Type": "application/json",
    "Origin": "https://rpow2.com",
    "Referer": "https://rpow2.com/",
})

r = s.post("https://api.rpow2.com/challenge", headers={"Cookie": cookie}, timeout=15)
print(f"/challenge status={r.status_code}")
print(r.text[:600])
