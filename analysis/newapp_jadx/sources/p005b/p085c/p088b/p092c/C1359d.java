package p005b.p085c.p088b.p092c;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.PackageInfo;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.os.Build;
import android.preference.PreferenceManager;
import android.text.TextUtils;
import android.widget.TextView;
import com.jbzd.media.movecartoons.bean.response.ChatMsgBean;
import java.io.File;
import java.util.HashMap;
import java.util.Objects;
import java.util.Random;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import net.sourceforge.pinyin4j.ChineseToPinyinResource;
import p005b.p085c.p088b.p089a.C1348e;
import p005b.p085c.p088b.p089a.p090h.C1353c;
import p005b.p085c.p088b.p091b.C1355a;
import p005b.p085c.p088b.p098h.C1373a;
import p005b.p085c.p088b.p098h.C1374b;
import p005b.p085c.p088b.p099i.C1375a;
import p005b.p085c.p088b.p100j.C1377b;
import p005b.p085c.p088b.p100j.C1383h;
import p005b.p131d.p132a.p133a.C1499a;

/* renamed from: b.c.b.c.d */
/* loaded from: classes.dex */
public class C1359d {

    /* renamed from: a */
    public static volatile C1359d f1223a;

    /* renamed from: b */
    public String f1224b;

    /* renamed from: c */
    public String f1225c = "sdk-and-lite";

    /* renamed from: d */
    public String f1226d;

    public C1359d() {
        String str = C1348e.f1165a;
        if (TextUtils.isEmpty(str) || TextUtils.equals("cn", C1348e.f1165a)) {
            return;
        }
        this.f1225c += '_' + str;
    }

    /* renamed from: a */
    public static String m382a(Context context) {
        if (context == null) {
            return "";
        }
        try {
            StringBuilder sb = new StringBuilder();
            String packageName = context.getPackageName();
            PackageInfo packageInfo = context.getPackageManager().getPackageInfo(packageName, 0);
            sb.append(ChineseToPinyinResource.Field.LEFT_BRACKET);
            sb.append(packageName);
            sb.append(";");
            sb.append(packageInfo.versionCode);
            sb.append(ChineseToPinyinResource.Field.RIGHT_BRACKET);
            return sb.toString();
        } catch (Exception unused) {
            return "";
        }
    }

    /* renamed from: c */
    public static synchronized void m383c(String str) {
        synchronized (C1359d.class) {
            if (TextUtils.isEmpty(str)) {
                return;
            }
            PreferenceManager.getDefaultSharedPreferences(C1374b.m417a().f1259b).edit().putString("trideskey", str).apply();
            C1355a.f1194a = str;
        }
    }

    /* renamed from: d */
    public static synchronized C1359d m384d() {
        C1359d c1359d;
        synchronized (C1359d.class) {
            if (f1223a == null) {
                f1223a = new C1359d();
            }
            c1359d = f1223a;
        }
        return c1359d;
    }

    /* renamed from: e */
    public static String m385e() {
        String hexString = Long.toHexString(System.currentTimeMillis());
        Random random = new Random();
        StringBuilder m586H = C1499a.m586H(hexString);
        m586H.append(random.nextInt(9000) + 1000);
        return m586H.toString();
    }

    /* renamed from: b */
    public String m386b(C1373a c1373a, C1375a c1375a) {
        String str;
        Context context = C1374b.m417a().f1259b;
        C1377b m424a = C1377b.m424a(context);
        if (TextUtils.isEmpty(this.f1224b)) {
            StringBuilder m586H = C1499a.m586H("Android ");
            m586H.append(Build.VERSION.RELEASE);
            String sb = m586H.toString();
            String m448l = C1383h.m448l();
            String locale = context.getResources().getConfiguration().locale.toString();
            TextUtils.isEmpty("https://mobilegw.alipay.com/mgw.htm");
            String m450n = C1383h.m450n(context);
            String f2 = Float.toString(new TextView(context).getTextSize());
            StringBuilder sb2 = new StringBuilder();
            sb2.append("Msp/15.7.7");
            sb2.append(" (");
            sb2.append(sb);
            sb2.append(";");
            sb2.append(m448l);
            C1499a.m608b0(sb2, ";", locale, ";", "https");
            sb2.append(";");
            sb2.append(m450n);
            sb2.append(";");
            sb2.append(f2);
            this.f1224b = sb2.toString();
        }
        String str2 = C1377b.m425b(context).f1290v;
        Objects.requireNonNull(m424a);
        Context context2 = C1374b.m417a().f1259b;
        boolean z = false;
        SharedPreferences sharedPreferences = context2.getSharedPreferences("virtualImeiAndImsi", 0);
        String string = sharedPreferences.getString("virtual_imsi", null);
        if (TextUtils.isEmpty(string)) {
            if (TextUtils.isEmpty(C1375a.m420a(context2).f1262c)) {
                String m419c = C1374b.m417a().m419c();
                string = (TextUtils.isEmpty(m419c) || m419c.length() < 18) ? m385e() : m419c.substring(3, 18);
            } else {
                Objects.requireNonNull(C1377b.m424a(context2));
                string = "000000000000000";
            }
            sharedPreferences.edit().putString("virtual_imsi", string).apply();
        }
        Context context3 = C1374b.m417a().f1259b;
        SharedPreferences sharedPreferences2 = context3.getSharedPreferences("virtualImeiAndImsi", 0);
        String string2 = sharedPreferences2.getString("virtual_imei", null);
        if (TextUtils.isEmpty(string2)) {
            if (TextUtils.isEmpty(C1375a.m420a(context3).f1262c)) {
                string2 = m385e();
            } else {
                Objects.requireNonNull(C1377b.m424a(context3));
                string2 = "000000000000000";
            }
            sharedPreferences2.edit().putString("virtual_imei", string2).apply();
        }
        this.f1226d = c1375a.f1263d;
        String replace = Build.MANUFACTURER.replace(";", " ");
        String replace2 = Build.MODEL.replace(";", " ");
        String[] strArr = {"/system/app/Superuser.apk", "/sbin/su", "/system/bin/su", "/system/xbin/su", "/data/local/xbin/su", "/data/local/bin/su", "/system/sd/xbin/su", "/system/bin/failsafe/su", "/data/local/su", "/su/bin/su"};
        int i2 = 0;
        while (true) {
            if (i2 >= 10) {
                break;
            }
            if (new File(strArr[i2]).exists()) {
                z = true;
                break;
            }
            i2++;
        }
        String str3 = m424a.f1271b;
        WifiInfo connectionInfo = ((WifiManager) context.getApplicationContext().getSystemService("wifi")).getConnectionInfo();
        String ssid = connectionInfo != null ? connectionInfo.getSSID() : ChatMsgBean.SERVICE_ID;
        WifiInfo connectionInfo2 = ((WifiManager) context.getApplicationContext().getSystemService("wifi")).getConnectionInfo();
        String bssid = connectionInfo2 != null ? connectionInfo2.getBSSID() : "00";
        StringBuilder sb3 = new StringBuilder();
        C1499a.m608b0(sb3, this.f1224b, ";", str2, ";");
        C1499a.m608b0(sb3, "-1;-1", ";", "1", ";");
        C1499a.m608b0(sb3, "000000000000000", ";", "000000000000000", ";");
        C1499a.m608b0(sb3, this.f1226d, ";", replace, ";");
        sb3.append(replace2);
        sb3.append(";");
        sb3.append(z);
        sb3.append(";");
        C1499a.m608b0(sb3, str3, ";", "-1;-1", ";");
        C1499a.m608b0(sb3, this.f1225c, ";", string, ";");
        C1499a.m608b0(sb3, string2, ";", ssid, ";");
        sb3.append(bssid);
        HashMap hashMap = new HashMap();
        hashMap.put("tid", C1375a.m420a(context).f1262c);
        hashMap.put("utdid", C1374b.m417a().m419c());
        try {
            str = (String) Executors.newFixedThreadPool(2).submit(new CallableC1358c(c1373a, context, hashMap)).get(3000L, TimeUnit.MILLISECONDS);
        } catch (Throwable th) {
            C1353c.m363d(c1373a, "third", "GetApdidTimeout", th);
            str = "";
        }
        if (!TextUtils.isEmpty(str)) {
            sb3.append(";;;");
            sb3.append(str);
        }
        sb3.append(ChineseToPinyinResource.Field.RIGHT_BRACKET);
        return sb3.toString();
    }
}
