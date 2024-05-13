package top.rookiestwo;

import java.net.Socket;


public class TcpPacketExample {
    public static void main(String[] args) throws Exception {
        String host = "wheatserver.top";
        int port = 23333;
        Socket socket = new Socket(host, port);
        TCPPacket packetBuilder = new TCPPacket();
        // 连接已建立，你可以在这里使用socket.getInputStream()和socket.getOutputStream()
        // 来读取和写入数据。
        socket.close();
    }
}
