# burp_json_xss_finder_plugin
a simple burp plugin used to find "json xss"
## 0x01简介
该burp插件用于发现可能存在**json xss**的接口
> Json xss 一种接口返回的数据是json格式，但是响应的content-type没有设置为application/json，而设置为text/html，这在接口返回的数据可控时，会导致xss


## 0x02使用
在burp专业版的Extender模块中 ADD 该插件的jar包
![image.png](https://cdn.nlark.com/yuque/0/2022/png/22550391/1667403515114-f745b2ca-423a-4321-adb3-4b7a8893bf7a.png#clientId=u503c86b5-cbb2-4&crop=0&crop=0&crop=1&crop=1&from=paste&height=587&id=uc9d272f6&margin=%5Bobject%20Object%5D&name=image.png&originHeight=1174&originWidth=2522&originalType=binary&ratio=1&rotation=0&showTitle=false&size=98292&status=done&style=none&taskId=u0a36a93a-4f7a-46fc-bbc3-8803c65099b&title=&width=1261)
如果没有Errors就是导入成功，导入成功后会发现多了个Json Xss Finder的 tab

后续在使用浏览器中访问站点时就能被动地发现Json xss了
![image.png](https://cdn.nlark.com/yuque/0/2022/png/22550391/1667403657546-731b5700-014b-4a54-a74f-e1fdaea26f65.png#clientId=u503c86b5-cbb2-4&crop=0&crop=0&crop=1&crop=1&from=paste&height=818&id=u01d63617&margin=%5Bobject%20Object%5D&name=image.png&originHeight=1636&originWidth=2540&originalType=binary&ratio=1&rotation=0&showTitle=false&size=165427&status=done&style=none&taskId=u2dd63d43-1921-49e6-a78d-ce6b1c7b0bc&title=&width=1270)