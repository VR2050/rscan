package com.ta.utdid2.device;

import android.content.Context;
import android.os.Binder;
import android.provider.Settings;
import android.text.TextUtils;
import com.snail.antifake.deviceid.ShellAdbUtils;
import com.ta.utdid2.a.a.f;
import com.ta.utdid2.a.a.g;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.util.Random;
import java.util.regex.Pattern;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/* JADX INFO: loaded from: classes3.dex */
public class c {

    /* JADX INFO: renamed from: a, reason: collision with other field name */
    private com.ta.utdid2.b.a.c f20a;

    /* JADX INFO: renamed from: a, reason: collision with other field name */
    private d f21a;
    private com.ta.utdid2.b.a.c b;
    private String i;
    private String j;
    private Context mContext;
    private static final Object e = new Object();
    private static c a = null;
    private static final String k = ".UTSystemConfig" + File.separator + "Global";
    private String h = null;

    /* JADX INFO: renamed from: b, reason: collision with other field name */
    private Pattern f22b = Pattern.compile("[^0-9a-zA-Z=/+]+");

    private c(Context context) {
        this.mContext = null;
        this.f21a = null;
        this.i = "xx_utdid_key";
        this.j = "xx_utdid_domain";
        this.f20a = null;
        this.b = null;
        this.mContext = context;
        this.b = new com.ta.utdid2.b.a.c(context, k, "Alvin2", false, true);
        this.f20a = new com.ta.utdid2.b.a.c(context, ".DataStorage", "ContextData", false, true);
        this.f21a = new d();
        this.i = String.format("K_%d", Integer.valueOf(g.a(this.i)));
        this.j = String.format("D_%d", Integer.valueOf(g.a(this.j)));
    }

    private void c() throws Throwable {
        com.ta.utdid2.b.a.c cVar = this.b;
        if (cVar != null) {
            if (g.m17a(cVar.getString("UTDID2"))) {
                String string = this.b.getString("UTDID");
                if (!g.m17a(string)) {
                    f(string);
                }
            }
            boolean z = false;
            boolean z2 = true;
            if (!g.m17a(this.b.getString("DID"))) {
                this.b.remove("DID");
                z = true;
            }
            if (!g.m17a(this.b.getString("EI"))) {
                this.b.remove("EI");
                z = true;
            }
            if (g.m17a(this.b.getString("SI"))) {
                z2 = z;
            } else {
                this.b.remove("SI");
            }
            if (z2) {
                this.b.commit();
            }
        }
    }

    public static c a(Context context) {
        if (context != null && a == null) {
            synchronized (e) {
                if (a == null) {
                    c cVar = new c(context);
                    a = cVar;
                    cVar.c();
                }
            }
        }
        return a;
    }

    private void f(String str) throws Throwable {
        com.ta.utdid2.b.a.c cVar;
        if (b(str)) {
            if (str.endsWith(ShellAdbUtils.COMMAND_LINE_END)) {
                str = str.substring(0, str.length() - 1);
            }
            if (str.length() == 24 && (cVar = this.b) != null) {
                cVar.putString("UTDID2", str);
                this.b.commit();
            }
        }
    }

    private void g(String str) throws Throwable {
        com.ta.utdid2.b.a.c cVar;
        if (str != null && (cVar = this.f20a) != null && !str.equals(cVar.getString(this.i))) {
            this.f20a.putString(this.i, str);
            this.f20a.commit();
        }
    }

    private void h(String str) {
        if (f() && b(str)) {
            if (str.endsWith(ShellAdbUtils.COMMAND_LINE_END)) {
                str = str.substring(0, str.length() - 1);
            }
            if (24 == str.length()) {
                String string = null;
                try {
                    string = Settings.System.getString(this.mContext.getContentResolver(), "mqBRboGZkQPcAkyk");
                } catch (Exception e2) {
                }
                if (!b(string)) {
                    try {
                        Settings.System.putString(this.mContext.getContentResolver(), "mqBRboGZkQPcAkyk", str);
                    } catch (Exception e3) {
                    }
                }
            }
        }
    }

    private void i(String str) {
        String string;
        try {
            string = Settings.System.getString(this.mContext.getContentResolver(), "dxCRMxhQkdGePGnp");
        } catch (Exception e2) {
            string = null;
        }
        if (!str.equals(string)) {
            try {
                Settings.System.putString(this.mContext.getContentResolver(), "dxCRMxhQkdGePGnp", str);
            } catch (Exception e3) {
            }
        }
    }

    private void j(String str) {
        if (f() && str != null) {
            i(str);
        }
    }

    private String g() throws Throwable {
        com.ta.utdid2.b.a.c cVar = this.b;
        if (cVar != null) {
            String string = cVar.getString("UTDID2");
            if (!g.m17a(string) && this.f21a.c(string) != null) {
                return string;
            }
            return null;
        }
        return null;
    }

    private boolean b(String str) {
        if (str != null) {
            if (str.endsWith(ShellAdbUtils.COMMAND_LINE_END)) {
                str = str.substring(0, str.length() - 1);
            }
            if (24 == str.length() && !this.f22b.matcher(str).find()) {
                return true;
            }
        }
        return false;
    }

    public synchronized String getValue() {
        if (this.h != null) {
            return this.h;
        }
        return h();
    }

    public synchronized String h() {
        String strI = i();
        this.h = strI;
        if (!TextUtils.isEmpty(strI)) {
            return this.h;
        }
        try {
            byte[] bArrM24c = m24c();
            if (bArrM24c != null) {
                String strEncodeToString = com.ta.utdid2.a.a.b.encodeToString(bArrM24c, 2);
                this.h = strEncodeToString;
                f(strEncodeToString);
                String strC = this.f21a.c(bArrM24c);
                if (strC != null) {
                    j(strC);
                    g(strC);
                }
                return this.h;
            }
        } catch (Exception e2) {
            e2.printStackTrace();
        }
        return null;
    }

    public synchronized String i() {
        String string;
        String string2 = "";
        try {
            string2 = Settings.System.getString(this.mContext.getContentResolver(), "mqBRboGZkQPcAkyk");
        } catch (Exception e2) {
        }
        if (b(string2)) {
            return string2;
        }
        e eVar = new e();
        boolean z = false;
        try {
            string = Settings.System.getString(this.mContext.getContentResolver(), "dxCRMxhQkdGePGnp");
        } catch (Exception e3) {
            string = null;
        }
        if (!g.m17a(string)) {
            String strE = eVar.e(string);
            if (b(strE)) {
                h(strE);
                return strE;
            }
            String strD = eVar.d(string);
            if (b(strD)) {
                String strC = this.f21a.c(strD);
                if (!g.m17a(strC)) {
                    j(strC);
                    try {
                        string = Settings.System.getString(this.mContext.getContentResolver(), "dxCRMxhQkdGePGnp");
                    } catch (Exception e4) {
                    }
                }
            }
            String strD2 = this.f21a.d(string);
            if (b(strD2)) {
                this.h = strD2;
                f(strD2);
                g(string);
                h(this.h);
                return this.h;
            }
        } else {
            z = true;
        }
        String strG = g();
        if (b(strG)) {
            String strC2 = this.f21a.c(strG);
            if (z) {
                j(strC2);
            }
            h(strG);
            g(strC2);
            this.h = strG;
            return strG;
        }
        String string3 = this.f20a.getString(this.i);
        if (!g.m17a(string3)) {
            String strD3 = eVar.d(string3);
            if (!b(strD3)) {
                strD3 = this.f21a.d(string3);
            }
            if (b(strD3)) {
                String strC3 = this.f21a.c(strD3);
                if (!g.m17a(strD3)) {
                    this.h = strD3;
                    if (z) {
                        j(strC3);
                    }
                    f(this.h);
                    return this.h;
                }
            }
        }
        return null;
    }

    /* JADX INFO: renamed from: c, reason: collision with other method in class */
    private byte[] m24c() throws Exception {
        String strA;
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        int iCurrentTimeMillis = (int) (System.currentTimeMillis() / 1000);
        int iNextInt = new Random().nextInt();
        byte[] bytes = com.ta.utdid2.a.a.d.getBytes(iCurrentTimeMillis);
        byte[] bytes2 = com.ta.utdid2.a.a.d.getBytes(iNextInt);
        byteArrayOutputStream.write(bytes, 0, 4);
        byteArrayOutputStream.write(bytes2, 0, 4);
        byteArrayOutputStream.write(3);
        byteArrayOutputStream.write(0);
        try {
            strA = com.ta.utdid2.a.a.e.a(this.mContext);
        } catch (Exception e2) {
            strA = "" + new Random().nextInt();
        }
        byteArrayOutputStream.write(com.ta.utdid2.a.a.d.getBytes(g.a(strA)), 0, 4);
        byteArrayOutputStream.write(com.ta.utdid2.a.a.d.getBytes(g.a(b(byteArrayOutputStream.toByteArray()))));
        return byteArrayOutputStream.toByteArray();
    }

    public static String b(byte[] bArr) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(new SecretKeySpec(f.a(new byte[]{69, 114, 116, -33, 125, -54, -31, 86, -11, 11, -78, -96, -17, -99, 64, 23, -95, -126, -82, -64, 113, 116, -16, -103, 49, -30, 9, -39, 33, -80, -68, -78, -117, 53, 30, -122, 64, -104, 74, -49, 106, 85, -38, -93}), mac.getAlgorithm()));
        return com.ta.utdid2.a.a.b.encodeToString(mac.doFinal(bArr), 2);
    }

    private boolean f() {
        return this.mContext.checkPermission("android.permission.WRITE_SETTINGS", Binder.getCallingPid(), Binder.getCallingUid()) == 0;
    }
}
