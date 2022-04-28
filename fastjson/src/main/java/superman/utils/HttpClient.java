package superman.utils;

import javax.net.ssl.*;
import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.*;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class HttpClient {
    private static String PROXY_IP = "127.0.0.1";
    private static int PROXY_PORT = 8080;
    private static boolean USE_PROXY = false;
    private static int CONNECT_TIME_OUT = 15 * 1000;
    private static int READ_TIME_OUT = 15 * 1000;
    private static String POST = "POST";
    private static String GET = "GET";
    private static final TrustManager[] trustAllCerts = new TrustManager[]{new X509TrustManager() {
        public X509Certificate[] getAcceptedIssuers() {
            return null;
        }
        public void checkClientTrusted(X509Certificate[] certs, String authType) {
        }
        public void checkServerTrusted(X509Certificate[] certs, String authType) {
        }
    }};
    private static final HostnameVerifier NOT_VERYFY = new HostnameVerifier() {
        @Override
        public boolean verify(String s, SSLSession sslSession) {
            return true;
        }
    };
    public static HttpResult get(String url) throws Exception {
        return get(url,null);
    }
    public static HttpResult get(String url, Map<String, String> headers) throws Exception {
        return httpRequest(url, GET,null, headers);
    }

    public static HttpResult post(String url, Map<String,String> data) throws Exception {
        Map<String, String> headers=new HashMap<String, String>();
        headers.put("Content-Type", "application/x-www-form-urlencoded");
        return post(url, data, headers);
    }
    public static HttpResult post(String url, Map<String,String> data, Map<String, String> headers) throws Exception {
        StringBuilder sb=new StringBuilder();
        for(String name:data.keySet()){
            String value=data.get(name);
            if(sb.length()>0){
                sb.append("&"+name+"="+URLEncoder.encode(value, "UTF-8" ));
            }else{
                sb.append(name+"="+URLEncoder.encode(value, "UTF-8" ));
            }
        }
        return httpRequest(url, POST,sb.toString().getBytes(), headers);
    }
    public static HttpResult post(String url, byte[] data, Map<String, String> headers) throws Exception {
        return httpRequest(url, POST,data, headers);
    }
    public static HttpResult post(String url, byte[] data) throws Exception {
        return httpRequest(url, POST,data, null);
    }
    public static HttpResult post(String url, String json) throws Exception {
        return httpRequest(url, POST,json.getBytes(), null);
    }
    public static HttpResult post(String url, String json, Map<String, String> headers) throws Exception {
        return httpRequest(url, POST,json.getBytes(), headers);
    }
    private static HttpResult httpRequest(String url,String method, byte[] data, Map<String, String> headers) throws Exception {
        URL u = new URL(url);
        HttpURLConnection con =null;
        if(url.toLowerCase().startsWith("https")){
            HttpsURLConnection.setDefaultHostnameVerifier(NOT_VERYFY);
            SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(null, trustAllCerts, new SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
        }
        if(USE_PROXY){
            Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress(PROXY_IP, PROXY_PORT));
            con = (HttpURLConnection) u.openConnection(proxy);
        }else{
            con = (HttpURLConnection) u.openConnection();
        }
        con.setConnectTimeout(CONNECT_TIME_OUT);
        con.setReadTimeout(READ_TIME_OUT);
        con.setRequestMethod(method);

        if (headers != null) {
            for (String key : headers.keySet()) {
                con.setRequestProperty(key, headers.get(key));
            }
        }
        if(method.equals(POST)){
            con.setDoOutput(true);
            OutputStream out = con.getOutputStream();
            out.write(data);
            out.flush();
            out.close();
        }
        HttpResult result=null;
        InputStream in = con.getInputStream();
        if (in != null) {
            BufferedReader reader = new BufferedReader(new InputStreamReader(in));
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line + "\n");
            }
            int code = con.getResponseCode();
            String text = sb.toString();
            Map<String, List<String>> responseHeaders = con.getHeaderFields();
            reader.close();
            result=new HttpResult(code, text, responseHeaders);
        }
        con.disconnect();
        return result;
    }
}

