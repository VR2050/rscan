package com.blankj.utilcode.util;

import android.content.Intent;
import android.net.Uri;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.os.Build;
import android.provider.Settings;
import android.telephony.TelephonyManager;
import android.text.TextUtils;
import com.blankj.utilcode.util.ShellUtils;
import com.snail.antifake.deviceid.ShellAdbUtils;
import java.io.File;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.Enumeration;
import java.util.UUID;

/* JADX INFO: loaded from: classes.dex */
public final class DeviceUtils {
    private static final String KEY_UDID = "KEY_UDID";
    private static volatile String udid;

    private DeviceUtils() {
        throw new UnsupportedOperationException("u can't instantiate me...");
    }

    public static boolean isDeviceRooted() {
        String[] locations = {"/system/bin/", "/system/xbin/", "/sbin/", "/system/sd/xbin/", "/system/bin/failsafe/", "/data/local/xbin/", "/data/local/bin/", "/data/local/", "/system/sbin/", "/usr/bin/", "/vendor/bin/"};
        for (String location : locations) {
            if (new File(location + ShellAdbUtils.COMMAND_SU).exists()) {
                return true;
            }
        }
        return false;
    }

    public static boolean isAdbEnabled() {
        return Settings.Secure.getInt(Utils.getApp().getContentResolver(), "adb_enabled", 0) > 0;
    }

    public static String getSDKVersionName() {
        return Build.VERSION.RELEASE;
    }

    public static int getSDKVersionCode() {
        return Build.VERSION.SDK_INT;
    }

    public static String getAndroidID() {
        String id = Settings.Secure.getString(Utils.getApp().getContentResolver(), "android_id");
        return ("9774d56d682e549c".equals(id) || id == null) ? "" : id;
    }

    public static String getMacAddress() {
        String[] strArr = (String[]) null;
        String macAddress = getMacAddress(strArr);
        if (!macAddress.equals("") || getWifiEnabled()) {
            return macAddress;
        }
        setWifiEnabled(true);
        setWifiEnabled(false);
        return getMacAddress(strArr);
    }

    private static boolean getWifiEnabled() {
        WifiManager manager = (WifiManager) Utils.getApp().getSystemService("wifi");
        if (manager == null) {
            return false;
        }
        return manager.isWifiEnabled();
    }

    private static void setWifiEnabled(boolean enabled) {
        WifiManager manager = (WifiManager) Utils.getApp().getSystemService("wifi");
        if (manager == null || enabled == manager.isWifiEnabled()) {
            return;
        }
        manager.setWifiEnabled(enabled);
    }

    public static String getMacAddress(String... excepts) {
        String macAddress = getMacAddressByNetworkInterface();
        if (isAddressNotInExcepts(macAddress, excepts)) {
            return macAddress;
        }
        String macAddress2 = getMacAddressByInetAddress();
        if (isAddressNotInExcepts(macAddress2, excepts)) {
            return macAddress2;
        }
        String macAddress3 = getMacAddressByWifiInfo();
        if (isAddressNotInExcepts(macAddress3, excepts)) {
            return macAddress3;
        }
        String macAddress4 = getMacAddressByFile();
        if (isAddressNotInExcepts(macAddress4, excepts)) {
            return macAddress4;
        }
        return "";
    }

    private static boolean isAddressNotInExcepts(String address, String... excepts) {
        if (excepts == null || excepts.length == 0) {
            return true ^ "02:00:00:00:00:00".equals(address);
        }
        for (String filter : excepts) {
            if (address.equals(filter)) {
                return false;
            }
        }
        return true;
    }

    private static String getMacAddressByWifiInfo() {
        WifiInfo info;
        try {
            WifiManager wifi = (WifiManager) Utils.getApp().getApplicationContext().getSystemService("wifi");
            return (wifi == null || (info = wifi.getConnectionInfo()) == null) ? "02:00:00:00:00:00" : info.getMacAddress();
        } catch (Exception e) {
            e.printStackTrace();
            return "02:00:00:00:00:00";
        }
    }

    private static String getMacAddressByNetworkInterface() {
        byte[] macBytes;
        try {
            Enumeration<NetworkInterface> nis = NetworkInterface.getNetworkInterfaces();
            while (nis.hasMoreElements()) {
                NetworkInterface ni = nis.nextElement();
                if (ni != null && ni.getName().equalsIgnoreCase("wlan0") && (macBytes = ni.getHardwareAddress()) != null && macBytes.length > 0) {
                    StringBuilder sb = new StringBuilder();
                    for (byte b : macBytes) {
                        sb.append(String.format("%02x:", Byte.valueOf(b)));
                    }
                    return sb.substring(0, sb.length() - 1);
                }
            }
            return "02:00:00:00:00:00";
        } catch (Exception e) {
            e.printStackTrace();
            return "02:00:00:00:00:00";
        }
    }

    private static String getMacAddressByInetAddress() {
        NetworkInterface ni;
        byte[] macBytes;
        try {
            InetAddress inetAddress = getInetAddress();
            if (inetAddress != null && (ni = NetworkInterface.getByInetAddress(inetAddress)) != null && (macBytes = ni.getHardwareAddress()) != null && macBytes.length > 0) {
                StringBuilder sb = new StringBuilder();
                for (byte b : macBytes) {
                    sb.append(String.format("%02x:", Byte.valueOf(b)));
                }
                return sb.substring(0, sb.length() - 1);
            }
            return "02:00:00:00:00:00";
        } catch (Exception e) {
            e.printStackTrace();
            return "02:00:00:00:00:00";
        }
    }

    private static InetAddress getInetAddress() {
        try {
            Enumeration<NetworkInterface> nis = NetworkInterface.getNetworkInterfaces();
            while (nis.hasMoreElements()) {
                NetworkInterface ni = nis.nextElement();
                if (ni.isUp()) {
                    Enumeration<InetAddress> addresses = ni.getInetAddresses();
                    while (addresses.hasMoreElements()) {
                        InetAddress inetAddress = addresses.nextElement();
                        if (!inetAddress.isLoopbackAddress()) {
                            String hostAddress = inetAddress.getHostAddress();
                            if (hostAddress.indexOf(58) < 0) {
                                return inetAddress;
                            }
                        }
                    }
                }
            }
            return null;
        } catch (SocketException e) {
            e.printStackTrace();
            return null;
        }
    }

    private static String getMacAddressByFile() {
        String name;
        String address;
        ShellUtils.CommandResult result = ShellUtils.execCmd("getprop wifi.interface", false);
        if (result.result == 0 && (name = result.successMsg) != null) {
            ShellUtils.CommandResult result2 = ShellUtils.execCmd("cat /sys/class/net/" + name + "/address", false);
            if (result2.result == 0 && (address = result2.successMsg) != null && address.length() > 0) {
                return address;
            }
            return "02:00:00:00:00:00";
        }
        return "02:00:00:00:00:00";
    }

    public static String getManufacturer() {
        return Build.MANUFACTURER;
    }

    public static String getModel() {
        String model = Build.MODEL;
        if (model != null) {
            return model.trim().replaceAll("\\s*", "");
        }
        return "";
    }

    public static String[] getABIs() {
        if (Build.VERSION.SDK_INT >= 21) {
            return Build.SUPPORTED_ABIS;
        }
        if (!TextUtils.isEmpty(Build.CPU_ABI2)) {
            return new String[]{Build.CPU_ABI, Build.CPU_ABI2};
        }
        return new String[]{Build.CPU_ABI};
    }

    public static boolean isTablet() {
        return (Utils.getApp().getResources().getConfiguration().screenLayout & 15) >= 3;
    }

    public static boolean isEmulator() {
        String name;
        boolean checkProperty = Build.FINGERPRINT.startsWith("generic") || Build.FINGERPRINT.toLowerCase().contains("vbox") || Build.FINGERPRINT.toLowerCase().contains("test-keys") || Build.MODEL.contains("google_sdk") || Build.MODEL.contains("Emulator") || Build.MODEL.contains("Android SDK built for x86") || Build.MANUFACTURER.contains("Genymotion") || (Build.BRAND.startsWith("generic") && Build.DEVICE.startsWith("generic")) || "google_sdk".equals(Build.PRODUCT);
        if (checkProperty) {
            return true;
        }
        String operatorName = "";
        TelephonyManager tm = (TelephonyManager) Utils.getApp().getSystemService("phone");
        if (tm != null && (name = tm.getNetworkOperatorName()) != null) {
            operatorName = name;
        }
        boolean checkOperatorName = operatorName.toLowerCase().equals("android");
        if (checkOperatorName) {
            return true;
        }
        Intent intent = new Intent();
        intent.setData(Uri.parse("tel:123456"));
        intent.setAction("android.intent.action.DIAL");
        boolean checkDial = intent.resolveActivity(Utils.getApp().getPackageManager()) == null;
        return checkDial;
    }

    public static String getUniqueDeviceId() {
        return getUniqueDeviceId("");
    }

    public static String getUniqueDeviceId(String prefix) {
        if (udid == null) {
            synchronized (DeviceUtils.class) {
                if (udid == null) {
                    String id = Utils.getSpUtils4Utils().getString(KEY_UDID, null);
                    if (id != null) {
                        udid = id;
                        return udid;
                    }
                    try {
                        String androidId = getAndroidID();
                        if (!TextUtils.isEmpty(androidId)) {
                            return saveUdid(prefix + 2, androidId);
                        }
                    } catch (Exception e) {
                    }
                    return saveUdid(prefix + 9, "");
                }
            }
        }
        return udid;
    }

    public static boolean isSameDevice(String uniqueDeviceId) {
        if (TextUtils.isEmpty(uniqueDeviceId) && uniqueDeviceId.length() < 33) {
            return false;
        }
        if (uniqueDeviceId.equals(udid)) {
            return true;
        }
        String cachedId = Utils.getSpUtils4Utils().getString(KEY_UDID, null);
        if (uniqueDeviceId.equals(cachedId)) {
            return true;
        }
        int st = uniqueDeviceId.length() - 33;
        String type = uniqueDeviceId.substring(st, st + 1);
        if (!type.startsWith("2")) {
            return false;
        }
        String androidId = getAndroidID();
        if (TextUtils.isEmpty(androidId)) {
            return false;
        }
        return uniqueDeviceId.substring(st + 1).equals(getUdid("", androidId));
    }

    private static String saveUdid(String prefix, String id) {
        udid = getUdid(prefix, id);
        SPUtils.getInstance().put(KEY_UDID, udid);
        return udid;
    }

    private static String getUdid(String prefix, String id) {
        if (id.equals("")) {
            return prefix + UUID.randomUUID().toString().replace("-", "");
        }
        return prefix + UUID.nameUUIDFromBytes(id.getBytes()).toString().replace("-", "");
    }
}
