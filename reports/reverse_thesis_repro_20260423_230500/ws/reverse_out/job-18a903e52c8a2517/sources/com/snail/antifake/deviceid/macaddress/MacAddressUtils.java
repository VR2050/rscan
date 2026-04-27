package com.snail.antifake.deviceid.macaddress;

import android.app.Application;
import android.content.Context;
import android.net.wifi.ScanResult;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.os.Build;
import android.text.TextUtils;
import com.snail.antifake.deviceid.ShellAdbUtils;
import java.lang.reflect.Method;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.Enumeration;
import java.util.List;

/* JADX INFO: loaded from: classes3.dex */
public class MacAddressUtils {
    public static String getMacAddress(Context context) throws SocketException {
        String macAddress = getMacInfoByAdb();
        if (!TextUtils.isEmpty(macAddress)) {
            return macAddress;
        }
        String macAddress2 = getMacAddressByWlan0(context);
        if (!TextUtils.isEmpty(macAddress2)) {
            return macAddress2;
        }
        String macAddress3 = IWifiManagerUtil.getMacAddress(context);
        return !TextUtils.isEmpty(macAddress3) ? macAddress3 : "";
    }

    public static String getMacInfoByAdb() {
        ShellAdbUtils.CommandResult commandResult = ShellAdbUtils.execCommand("cat /sys/class/net/wlan0/address", false);
        return commandResult.successMsg;
    }

    private static String getProp(Context context, String property) {
        try {
            ClassLoader cl = context.getClassLoader();
            Class<?> SystemProperties = cl.loadClass("android.os.SystemProperties");
            Method method = SystemProperties.getDeclaredMethod("native_get", String.class);
            Object[] params = {property};
            method.setAccessible(true);
            return (String) method.invoke(SystemProperties, params);
        } catch (Exception e) {
            return null;
        }
    }

    public static String getMacAddressByWlan0(Context context) throws SocketException {
        Enumeration<NetworkInterface> interfaces = null;
        try {
            interfaces = NetworkInterface.getNetworkInterfaces();
        } catch (SocketException e) {
            e.printStackTrace();
        }
        while (interfaces.hasMoreElements()) {
            NetworkInterface iF = interfaces.nextElement();
            byte[] addr = new byte[0];
            if (Build.VERSION.SDK_INT >= 9) {
                try {
                    addr = iF.getHardwareAddress();
                } catch (SocketException e2) {
                    e2.printStackTrace();
                }
            }
            if (iF.getDisplayName().equals(getProp(context, "wifi.interface")) && addr != null && addr.length != 0) {
                StringBuilder buf = new StringBuilder();
                for (byte b : addr) {
                    buf.append(String.format("%02X:", Byte.valueOf(b)));
                }
                if (buf.length() > 0) {
                    buf.deleteCharAt(buf.length() - 1);
                }
                String mac = buf.toString();
                return mac;
            }
        }
        return "";
    }

    public static String getConnectedWifiMacAddress(Application context) {
        String connectedWifiMacAddress = null;
        WifiManager wifiManager = (WifiManager) context.getSystemService("wifi");
        if (wifiManager != null) {
            List<ScanResult> wifiList = wifiManager.getScanResults();
            WifiInfo info = wifiManager.getConnectionInfo();
            if (wifiList != null && info != null) {
                for (int i = 0; i < wifiList.size(); i++) {
                    ScanResult result = wifiList.get(i);
                    if (!TextUtils.isEmpty(info.getBSSID()) && info.getBSSID().equals(result.BSSID)) {
                        connectedWifiMacAddress = result.BSSID;
                    }
                }
            }
        }
        return connectedWifiMacAddress;
    }
}
