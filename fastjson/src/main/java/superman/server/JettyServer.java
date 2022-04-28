package superman.server;

import javassist.ClassPool;
import javassist.CtClass;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.servlet.ServletHandler;
import superman.utils.ClassUtil;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.net.URLEncoder;
import java.util.logging.Level;
import java.util.logging.Logger;

public class JettyServer implements Runnable {
    private int port;
    private Server server;
    private String socketHost;
    private int socketPort;
    static byte[] transformed;


    public JettyServer(int port, byte[] payload) {
        this.port = port;
        System.setProperty("org.eclipse.jetty.LEVEL", "WARN");
        server = new Server(port);
        transformed=payload;
    }

    @Override
    public void run() {
        ServletHandler handler = new ServletHandler();
        server.setHandler(handler);

        handler.addServletWithMapping(DownloadServlet.class, "/*");
        try {
            server.start();
            server.join();
        } catch (Exception e) {
            e.printStackTrace();
        }

    }



    public static class DownloadServlet extends HttpServlet {
        public void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {

            String filename = request.getRequestURI().substring(1);

            ByteArrayInputStream bain = null;

            if (transformed != null) {
                try {
                    bain = new ByteArrayInputStream(transformed);
                } catch (Exception e) {
                    e.printStackTrace();
                    System.out.println("[JETTYSERVER]>> Byte array build failed.");
                }

                System.out.println("[JETTYSERVER]>> Log a request to " + request.getRequestURL());
                response.setStatus(HttpServletResponse.SC_OK);
                response.setHeader("content-disposition", "attachment;filename=" + URLEncoder.encode(filename, "UTF-8"));

                int len;
                byte[] buffer = new byte[1024];
                OutputStream out = response.getOutputStream();
                if (bain != null) {
                    while ((len = bain.read(buffer)) > 0) {
                        out.write(buffer, 0, len);
                    }
                    bain.close();
                } else {
                    System.out.println("[JETTYSERVER]>> Read file error!");
                }
            } else {
                System.out.println("[JETTYSERVER]>> URL(" + request.getRequestURL() + ") Not Exist!");
            }
        }

        public void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
            doGet(request, response);
        }
    }


}
