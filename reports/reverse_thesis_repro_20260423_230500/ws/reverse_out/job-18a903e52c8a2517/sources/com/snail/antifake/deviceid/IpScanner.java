package com.snail.antifake.deviceid;

import android.os.Handler;
import android.os.Looper;
import android.text.TextUtils;
import android.util.Log;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

/* JADX INFO: loaded from: classes3.dex */
public class IpScanner {
    private Handler mHandler = new Handler(Looper.getMainLooper());

    public interface OnScanListener {
        void scan(Map<String, String> map);
    }

    public void startScan(final OnScanListener listener) {
        new ArrayList();
        new HashMap();
        String hostIP = getHostIP();
        if (TextUtils.isEmpty(hostIP)) {
            return;
        }
        int lastIndexOf = hostIP.lastIndexOf(".");
        final String substring = hostIP.substring(0, lastIndexOf + 1);
        new Thread(new Runnable() { // from class: com.snail.antifake.deviceid.IpScanner.1
            @Override // java.lang.Runnable
            public void run() {
                DatagramPacket dp = new DatagramPacket(new byte[0], 0, 0);
                try {
                    DatagramSocket socket = new DatagramSocket();
                    int position = 2;
                    while (position < 255) {
                        Log.e("kalshen", "run: udp-" + substring + position);
                        StringBuilder sb = new StringBuilder();
                        sb.append(substring);
                        sb.append(String.valueOf(position));
                        dp.setAddress(InetAddress.getByName(sb.toString()));
                        socket.send(dp);
                        position++;
                        if (position == 125) {
                            socket.close();
                            socket = new DatagramSocket();
                        }
                    }
                    socket.close();
                    IpScanner.this.execCatForArp(listener);
                } catch (SocketException e) {
                    e.printStackTrace();
                } catch (UnknownHostException e2) {
                    e2.printStackTrace();
                } catch (IOException e3) {
                    e3.printStackTrace();
                }
            }
        }).start();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void execCatForArp(final OnScanListener listener) {
        new Thread(new Runnable() { // from class: com.snail.antifake.deviceid.IpScanner.2
            @Override // java.lang.Runnable
            public void run() {
                try {
                    final Map<String, String> map = new HashMap<>();
                    Process exec = Runtime.getRuntime().exec("cat proc/net/arp");
                    InputStream is = exec.getInputStream();
                    BufferedReader reader = new BufferedReader(new InputStreamReader(is));
                    while (true) {
                        String line = reader.readLine();
                        if (line == null) {
                            IpScanner.this.mHandler.post(new Runnable() { // from class: com.snail.antifake.deviceid.IpScanner.2.1
                                @Override // java.lang.Runnable
                                public void run() {
                                    listener.scan(map);
                                }
                            });
                            return;
                        }
                        Log.e("kalshen", "run: " + line);
                        if (!line.contains("00:00:00:00:00:00") && !line.contains("IP")) {
                            String[] split = line.split("\\s+");
                            map.put(split[3], split[0]);
                        }
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }).start();
    }

    private String getHostIP() {
        String hostIp = null;
        try {
            Enumeration<NetworkInterface> networkInterfaces = NetworkInterface.getNetworkInterfaces();
            while (networkInterfaces.hasMoreElements()) {
                NetworkInterface ni = networkInterfaces.nextElement();
                Enumeration<InetAddress> ias = ni.getInetAddresses();
                while (true) {
                    if (ias.hasMoreElements()) {
                        InetAddress ia = ias.nextElement();
                        if (!(ia instanceof Inet6Address)) {
                            String ip = ia.getHostAddress();
                            if (!"127.0.0.1".equals(ip)) {
                                hostIp = ia.getHostAddress();
                                break;
                            }
                        }
                    }
                }
            }
        } catch (SocketException e) {
            Log.i("kalshen", "SocketException");
            e.printStackTrace();
        }
        return hostIp;
    }
}
