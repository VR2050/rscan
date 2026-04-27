package io.openinstall.sdk;

import android.content.Context;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.os.Build;
import android.telephony.TelephonyManager;
import android.text.TextUtils;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.net.NetworkInterface;
import java.util.Collections;

/* JADX INFO: loaded from: classes3.dex */
public class s {
    private final Context a;
    private String b;
    private String c;

    public s(Context context) {
        this.a = context;
    }

    private boolean a(String str) {
        return TextUtils.isEmpty(str) || str.equals(dx.j) || str.equals(dx.k);
    }

    private boolean b(String str) {
        return TextUtils.isEmpty(str) || str.equals(dx.l);
    }

    public String a() {
        byte[] hardwareAddress;
        WifiInfo connectionInfo;
        String str = this.b;
        if (str != null) {
            return str;
        }
        String string = null;
        try {
            WifiManager wifiManager = (WifiManager) this.a.getSystemService(dx.f);
            if (wifiManager != null && (connectionInfo = wifiManager.getConnectionInfo()) != null) {
                string = connectionInfo.getMacAddress();
            }
        } catch (SecurityException e) {
        } catch (Throwable th) {
        }
        if (!b(string)) {
            this.b = string;
            return string;
        }
        try {
            string = new BufferedReader(new FileReader(new File(dx.h))).readLine();
        } catch (IOException e2) {
        } catch (Throwable th2) {
        }
        if (!b(string)) {
            this.b = string;
            return string;
        }
        try {
            for (NetworkInterface networkInterface : Collections.list(NetworkInterface.getNetworkInterfaces())) {
                if (dx.g.equalsIgnoreCase(networkInterface.getName()) && (hardwareAddress = networkInterface.getHardwareAddress()) != null) {
                    StringBuilder sb = new StringBuilder();
                    for (byte b : hardwareAddress) {
                        sb.append(String.format("%02X:", Byte.valueOf(b)));
                    }
                    if (sb.length() > 0) {
                        sb.deleteCharAt(sb.length() - 1);
                    }
                    string = sb.toString();
                }
            }
        } catch (Throwable th3) {
        }
        if (b(string)) {
            string = "";
        }
        this.b = string;
        return this.b;
    }

    public String b() {
        String str = this.c;
        if (str != null) {
            return str;
        }
        String imei = null;
        if (eb.a(this.a)) {
            TelephonyManager telephonyManager = (TelephonyManager) this.a.getSystemService("phone");
            try {
                imei = Build.VERSION.SDK_INT >= 26 ? telephonyManager.getImei() : telephonyManager.getDeviceId();
            } catch (SecurityException e) {
            } catch (Throwable th) {
            }
        }
        if (a(imei)) {
            imei = "";
        }
        this.c = imei;
        return this.c;
    }
}
