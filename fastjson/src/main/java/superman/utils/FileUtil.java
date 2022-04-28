package superman.utils;

import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.net.URLEncoder;

public class FileUtil {
    public static String readFile(String fileName) {
        try {
            InputStream in = Thread.currentThread().getContextClassLoader().getResourceAsStream(fileName);
            BufferedReader reader = new BufferedReader(new InputStreamReader(in));
            StringBuilder sb = new StringBuilder();
            String buf = null;
            while ((buf = reader.readLine()) != null) {
                sb.append(buf);
            }
            reader.close();
            in.close();
            return sb.toString();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }
}
