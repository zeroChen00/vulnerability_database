package superman.utils;

import java.util.List;
import java.util.Map;

public class HttpResult{
    private int code;
    private String data;
    private Map<String, List<String>> headers;

    public HttpResult(int code, String data, Map<String, List<String>> headers) {
        this.code = code;
        this.data = data;
        this.headers = headers;
    }

    public int getCode() {
        return code;
    }

    public void setCode(int code) {
        this.code = code;
    }

    public String getData() {
        return data;
    }

    public void setData(String data) {
        this.data = data;
    }

    public Map<String, List<String>> getHeaders() {
        return headers;
    }

    public void setHeaders(Map<String, List<String>> headers) {
        this.headers = headers;
    }
}