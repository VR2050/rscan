package p005b.p085c.p102c.p103a.p104a.p107b;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.os.Environment;
import android.os.StatFs;
import android.os.SystemClock;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import p005b.p085c.p102c.p103a.p104a.p105a.p106a.C1391a;

/* renamed from: b.c.c.a.a.b.a */
/* loaded from: classes.dex */
public final class C1393a {

    /* renamed from: a */
    public static C1393a f1324a = new C1393a();

    /* renamed from: a */
    public static boolean m464a(Context context, String str) {
        return !(context.getPackageManager().checkPermission(str, context.getPackageName()) == 0);
    }

    /* renamed from: b */
    public static String m465b() {
        long j2;
        try {
            StatFs statFs = new StatFs(Environment.getDataDirectory().getPath());
            j2 = statFs.getAvailableBlocks() * statFs.getBlockSize();
        } catch (Throwable unused) {
            j2 = 0;
        }
        return String.valueOf(j2);
    }

    /* renamed from: c */
    public static String m466c() {
        long j2 = 0;
        try {
            if ("mounted".equals(Environment.getExternalStorageState())) {
                File file = null;
                try {
                    file = (File) Environment.class.getMethod(new String(C1391a.m458a("Z2V0RXh0ZXJuYWxTdG9yYWdlRGlyZWN0b3J5")), new Class[0]).invoke(null, new Object[0]);
                } catch (Exception unused) {
                }
                StatFs statFs = new StatFs(file.getPath());
                j2 = statFs.getBlockSize() * statFs.getAvailableBlocks();
            }
        } catch (Throwable unused2) {
        }
        return String.valueOf(j2);
    }

    /* renamed from: d */
    public static String m467d() {
        BufferedReader bufferedReader;
        FileReader fileReader;
        String[] split;
        FileReader fileReader2 = null;
        try {
            fileReader = new FileReader("/proc/cpuinfo");
            try {
                bufferedReader = new BufferedReader(fileReader);
            } catch (Throwable unused) {
                bufferedReader = null;
            }
        } catch (Throwable unused2) {
            bufferedReader = null;
        }
        try {
            split = bufferedReader.readLine().split(":\\s+", 2);
        } catch (Throwable unused3) {
            fileReader2 = fileReader;
            if (fileReader2 != null) {
                try {
                    fileReader2.close();
                } catch (Throwable unused4) {
                }
            }
            if (bufferedReader == null) {
                return "";
            }
            try {
                bufferedReader.close();
                return "";
            } catch (Throwable unused5) {
                return "";
            }
        }
        if (split == null || split.length <= 1) {
            try {
                fileReader.close();
            } catch (Throwable unused6) {
            }
            bufferedReader.close();
            return "";
        }
        String str = split[1];
        try {
            fileReader.close();
        } catch (Throwable unused7) {
        }
        try {
            bufferedReader.close();
        } catch (Throwable unused8) {
        }
        return str;
    }

    /* renamed from: e */
    public static String m468e() {
        try {
            long currentTimeMillis = System.currentTimeMillis() - SystemClock.elapsedRealtime();
            StringBuilder sb = new StringBuilder();
            sb.append(currentTimeMillis - (currentTimeMillis % 1000));
            return sb.toString();
        } catch (Throwable unused) {
            return "";
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:10:0x0026  */
    /* JADX WARN: Removed duplicated region for block: B:12:? A[RETURN, SYNTHETIC] */
    /* renamed from: f */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static java.lang.String m469f(android.content.Context r2) {
        /*
            java.lang.String r0 = "android.permission.ACCESS_WIFI_STATE"
            boolean r0 = m464a(r2, r0)
            java.lang.String r1 = ""
            if (r0 == 0) goto Lb
            return r1
        Lb:
            java.lang.String r0 = "wifi"
            java.lang.Object r2 = r2.getSystemService(r0)     // Catch: java.lang.Throwable -> L22
            android.net.wifi.WifiManager r2 = (android.net.wifi.WifiManager) r2     // Catch: java.lang.Throwable -> L22
            boolean r0 = r2.isWifiEnabled()     // Catch: java.lang.Throwable -> L22
            if (r0 == 0) goto L22
            android.net.wifi.WifiInfo r2 = r2.getConnectionInfo()     // Catch: java.lang.Throwable -> L22
            java.lang.String r2 = r2.getBSSID()     // Catch: java.lang.Throwable -> L22
            goto L23
        L22:
            r2 = r1
        L23:
            if (r2 != 0) goto L26
            goto L27
        L26:
            r1 = r2
        L27:
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p085c.p102c.p103a.p104a.p107b.C1393a.m469f(android.content.Context):java.lang.String");
    }

    /* renamed from: g */
    public static String m470g(Context context) {
        if (m464a(context, "android.permission.ACCESS_NETWORK_STATE")) {
            return "";
        }
        try {
            NetworkInfo activeNetworkInfo = ((ConnectivityManager) context.getSystemService("connectivity")).getActiveNetworkInfo();
            if (activeNetworkInfo == null) {
                return null;
            }
            if (activeNetworkInfo.getType() == 1) {
                return "WIFI";
            }
            if (activeNetworkInfo.getType() != 0) {
                return null;
            }
            int subtype = activeNetworkInfo.getSubtype();
            if (subtype != 4 && subtype != 1 && subtype != 2 && subtype != 7 && subtype != 11) {
                if (subtype != 3 && subtype != 5 && subtype != 6 && subtype != 8 && subtype != 9 && subtype != 10 && subtype != 12 && subtype != 14 && subtype != 15) {
                    return subtype == 13 ? "4G" : "UNKNOW";
                }
                return "3G";
            }
            return "2G";
        } catch (Throwable unused) {
            return null;
        }
    }

    /* renamed from: h */
    public static String m471h() {
        try {
            ArrayList<NetworkInterface> list = Collections.list(NetworkInterface.getNetworkInterfaces());
            if (list == null) {
                return "02:00:00:00:00:00";
            }
            for (NetworkInterface networkInterface : list) {
                if (networkInterface != null && networkInterface.getName() != null && networkInterface.getName().equalsIgnoreCase("wlan0")) {
                    byte[] hardwareAddress = networkInterface.getHardwareAddress();
                    if (hardwareAddress == null) {
                        return "02:00:00:00:00:00";
                    }
                    StringBuilder sb = new StringBuilder();
                    for (byte b2 : hardwareAddress) {
                        sb.append(String.format("%02X:", Integer.valueOf(b2 & 255)));
                    }
                    if (sb.length() > 0) {
                        sb.deleteCharAt(sb.length() - 1);
                    }
                    return sb.toString();
                }
            }
            return "02:00:00:00:00:00";
        } catch (Throwable unused) {
            return "02:00:00:00:00:00";
        }
    }

    /* renamed from: i */
    public static String m472i() {
        try {
            Enumeration<NetworkInterface> networkInterfaces = NetworkInterface.getNetworkInterfaces();
            while (networkInterfaces.hasMoreElements()) {
                Enumeration<InetAddress> inetAddresses = networkInterfaces.nextElement().getInetAddresses();
                while (inetAddresses.hasMoreElements()) {
                    InetAddress nextElement = inetAddresses.nextElement();
                    if (!nextElement.isLoopbackAddress() && (nextElement instanceof Inet4Address)) {
                        return nextElement.getHostAddress().toString();
                    }
                }
            }
            return "";
        } catch (Throwable unused) {
            return "";
        }
    }
}
