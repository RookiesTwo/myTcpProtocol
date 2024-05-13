package top.rookiestwo;

import java.net.Socket;


public class TcpPacketExample {
    public static void main(String[] args) throws Exception {
        String host = "155.138.142.54";
        int port = 80;
        Socket socket = new Socket(host, port);
        // 连接已建立，你可以在这里使用socket.getInputStream()和socket.getOutputStream()
        // 来读取和写入数据。
        socket.getOutputStream().write("hello".getBytes());
        socket.close();
    }
}
