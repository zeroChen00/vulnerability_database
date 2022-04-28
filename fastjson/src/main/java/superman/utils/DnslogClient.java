package superman.utils;

import java.util.HashMap;
import java.util.Map;

public class DnslogClient {
    private String cookie = null;

    public String getdomain() throws Exception {
        String url = "http://www.dnslog.cn/getdomain.php";
        HttpResult result = HttpClient.get(url);
        cookie = result.getHeaders().get("Set-Cookie").get(0).split(";")[0];
        return result.getData().trim();
    }

    public String getRecords() throws Exception {
        String url = "http://www.dnslog.cn/getrecords.php";
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("Cookie", cookie);
        HttpResult result = HttpClient.get(url, headers);
        return result.getData().trim();
    }
}
