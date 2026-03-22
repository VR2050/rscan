package p005b.p085c.p088b.p100j;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.net.wifi.WifiManager;
import android.text.TextUtils;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.c.b.j.b */
/* loaded from: classes.dex */
public class C1377b {

    /* renamed from: a */
    public static C1377b f1270a;

    /* renamed from: b */
    public String f1271b;

    public C1377b(Context context) {
        try {
            try {
                String macAddress = ((WifiManager) context.getApplicationContext().getSystemService("wifi")).getConnectionInfo().getMacAddress();
                this.f1271b = macAddress;
                if (!TextUtils.isEmpty(macAddress)) {
                    return;
                }
            } catch (Exception e2) {
                C4195m.m4816l(e2);
                if (!TextUtils.isEmpty(this.f1271b)) {
                    return;
                }
            }
            this.f1271b = "00:00:00:00:00:00";
        } catch (Throwable th) {
            if (TextUtils.isEmpty(this.f1271b)) {
                this.f1271b = "00:00:00:00:00:00";
            }
            throw th;
        }
    }

    /* renamed from: a */
    public static C1377b m424a(Context context) {
        if (f1270a == null) {
            f1270a = new C1377b(context);
        }
        return f1270a;
    }

    /* renamed from: b */
    public static EnumC1378c m425b(Context context) {
        NetworkInfo activeNetworkInfo;
        EnumC1378c enumC1378c = EnumC1378c.NONE;
        try {
            activeNetworkInfo = ((ConnectivityManager) context.getApplicationContext().getSystemService("connectivity")).getActiveNetworkInfo();
        } catch (Exception unused) {
        }
        if (activeNetworkInfo == null || activeNetworkInfo.getType() != 0) {
            if (activeNetworkInfo != null && activeNetworkInfo.getType() == 1) {
                return EnumC1378c.WIFI;
            }
            return enumC1378c;
        }
        int subtype = activeNetworkInfo.getSubtype();
        EnumC1378c[] values = EnumC1378c.values();
        for (int i2 = 0; i2 < 16; i2++) {
            EnumC1378c enumC1378c2 = values[i2];
            if (enumC1378c2.f1289u == subtype) {
                return enumC1378c2;
            }
        }
        return enumC1378c;
    }
}
