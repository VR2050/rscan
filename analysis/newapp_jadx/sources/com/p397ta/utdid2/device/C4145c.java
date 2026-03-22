package com.p397ta.utdid2.device;

import android.content.Context;
import android.os.Binder;
import android.provider.Settings;
import android.text.TextUtils;
import androidx.exifinterface.media.ExifInterface;
import com.p397ta.utdid2.p398a.p399a.C4131b;
import com.p397ta.utdid2.p398a.p399a.C4133d;
import com.p397ta.utdid2.p398a.p399a.C4134e;
import com.p397ta.utdid2.p398a.p399a.C4135f;
import com.p397ta.utdid2.p398a.p399a.C4136g;
import com.p397ta.utdid2.p400b.p401a.C4140c;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.util.Random;
import java.util.regex.Pattern;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import p005b.p131d.p132a.p133a.C1499a;

/* renamed from: com.ta.utdid2.device.c */
/* loaded from: classes2.dex */
public class C4145c {

    /* renamed from: a */
    private static C4145c f10851a;

    /* renamed from: e */
    private static final Object f10852e = new Object();

    /* renamed from: k */
    private static final String f10853k = C1499a.m582D(C1499a.m586H(".UTSystemConfig"), File.separator, "Global");

    /* renamed from: a */
    private C4140c f10854a;

    /* renamed from: a */
    private C4146d f10855a;

    /* renamed from: b */
    private C4140c f10856b;

    /* renamed from: i */
    private String f10859i;

    /* renamed from: j */
    private String f10860j;
    private Context mContext;

    /* renamed from: h */
    private String f10858h = null;

    /* renamed from: b */
    private Pattern f10857b = Pattern.compile("[^0-9a-zA-Z=/+]+");

    private C4145c(Context context) {
        this.mContext = null;
        this.f10855a = null;
        this.f10859i = "xx_utdid_key";
        this.f10860j = "xx_utdid_domain";
        this.f10854a = null;
        this.f10856b = null;
        this.mContext = context;
        this.f10856b = new C4140c(context, f10853k, "Alvin2", false, true);
        this.f10854a = new C4140c(context, ".DataStorage", "ContextData", false, true);
        this.f10855a = new C4146d();
        this.f10859i = String.format("K_%d", Integer.valueOf(C4136g.m4660a(this.f10859i)));
        this.f10860j = String.format("D_%d", Integer.valueOf(C4136g.m4660a(this.f10860j)));
    }

    /* renamed from: a */
    public static C4145c m4724a(Context context) {
        if (context != null && f10851a == null) {
            synchronized (f10852e) {
                if (f10851a == null) {
                    C4145c c4145c = new C4145c(context);
                    f10851a = c4145c;
                    c4145c.m4727c();
                }
            }
        }
        return f10851a;
    }

    /* renamed from: b */
    private boolean m4726b(String str) {
        if (str != null) {
            if (str.endsWith("\n")) {
                str = str.substring(0, str.length() - 1);
            }
            if (24 == str.length() && !this.f10857b.matcher(str).find()) {
                return true;
            }
        }
        return false;
    }

    /* renamed from: c */
    private void m4727c() {
        C4140c c4140c = this.f10856b;
        if (c4140c != null) {
            if (C4136g.m4661a(c4140c.getString("UTDID2"))) {
                String string = this.f10856b.getString("UTDID");
                if (!C4136g.m4661a(string)) {
                    m4729f(string);
                }
            }
            boolean z = false;
            boolean z2 = true;
            if (!C4136g.m4661a(this.f10856b.getString("DID"))) {
                this.f10856b.remove("DID");
                z = true;
            }
            if (!C4136g.m4661a(this.f10856b.getString("EI"))) {
                this.f10856b.remove("EI");
                z = true;
            }
            if (C4136g.m4661a(this.f10856b.getString("SI"))) {
                z2 = z;
            } else {
                this.f10856b.remove("SI");
            }
            if (z2) {
                this.f10856b.commit();
            }
        }
    }

    /* renamed from: f */
    private void m4729f(String str) {
        C4140c c4140c;
        if (m4726b(str)) {
            if (str.endsWith("\n")) {
                str = str.substring(0, str.length() - 1);
            }
            if (str.length() != 24 || (c4140c = this.f10856b) == null) {
                return;
            }
            c4140c.putString("UTDID2", str);
            this.f10856b.commit();
        }
    }

    /* renamed from: g */
    private void m4732g(String str) {
        C4140c c4140c;
        if (str == null || (c4140c = this.f10854a) == null || str.equals(c4140c.getString(this.f10859i))) {
            return;
        }
        this.f10854a.putString(this.f10859i, str);
        this.f10854a.commit();
    }

    /* renamed from: h */
    private void m4733h(String str) {
        if (m4730f() && m4726b(str)) {
            if (str.endsWith("\n")) {
                str = str.substring(0, str.length() - 1);
            }
            if (24 == str.length()) {
                String str2 = null;
                try {
                    str2 = Settings.System.getString(this.mContext.getContentResolver(), "mqBRboGZkQPcAkyk");
                } catch (Exception unused) {
                }
                if (m4726b(str2)) {
                    return;
                }
                try {
                    Settings.System.putString(this.mContext.getContentResolver(), "mqBRboGZkQPcAkyk", str);
                } catch (Exception unused2) {
                }
            }
        }
    }

    /* renamed from: i */
    private void m4734i(String str) {
        String str2;
        try {
            str2 = Settings.System.getString(this.mContext.getContentResolver(), "dxCRMxhQkdGePGnp");
        } catch (Exception unused) {
            str2 = null;
        }
        if (str.equals(str2)) {
            return;
        }
        try {
            Settings.System.putString(this.mContext.getContentResolver(), "dxCRMxhQkdGePGnp", str);
        } catch (Exception unused2) {
        }
    }

    /* renamed from: j */
    private void m4735j(String str) {
        if (!m4730f() || str == null) {
            return;
        }
        m4734i(str);
    }

    public synchronized String getValue() {
        String str = this.f10858h;
        if (str != null) {
            return str;
        }
        return m4736h();
    }

    /* renamed from: i */
    public synchronized String m4737i() {
        String str;
        String str2 = "";
        try {
            str2 = Settings.System.getString(this.mContext.getContentResolver(), "mqBRboGZkQPcAkyk");
        } catch (Exception unused) {
        }
        if (m4726b(str2)) {
            return str2;
        }
        C4147e c4147e = new C4147e();
        boolean z = false;
        try {
            str = Settings.System.getString(this.mContext.getContentResolver(), "dxCRMxhQkdGePGnp");
        } catch (Exception unused2) {
            str = null;
        }
        if (C4136g.m4661a(str)) {
            z = true;
        } else {
            String m4742e = c4147e.m4742e(str);
            if (m4726b(m4742e)) {
                m4733h(m4742e);
                return m4742e;
            }
            String m4741d = c4147e.m4741d(str);
            if (m4726b(m4741d)) {
                String m4738c = this.f10855a.m4738c(m4741d);
                if (!C4136g.m4661a(m4738c)) {
                    m4735j(m4738c);
                    try {
                        str = Settings.System.getString(this.mContext.getContentResolver(), "dxCRMxhQkdGePGnp");
                    } catch (Exception unused3) {
                    }
                }
            }
            String m4740d = this.f10855a.m4740d(str);
            if (m4726b(m4740d)) {
                this.f10858h = m4740d;
                m4729f(m4740d);
                m4732g(str);
                m4733h(this.f10858h);
                return this.f10858h;
            }
        }
        String m4731g = m4731g();
        if (m4726b(m4731g)) {
            String m4738c2 = this.f10855a.m4738c(m4731g);
            if (z) {
                m4735j(m4738c2);
            }
            m4733h(m4731g);
            m4732g(m4738c2);
            this.f10858h = m4731g;
            return m4731g;
        }
        String string = this.f10854a.getString(this.f10859i);
        if (!C4136g.m4661a(string)) {
            String m4741d2 = c4147e.m4741d(string);
            if (!m4726b(m4741d2)) {
                m4741d2 = this.f10855a.m4740d(string);
            }
            if (m4726b(m4741d2)) {
                String m4738c3 = this.f10855a.m4738c(m4741d2);
                if (!C4136g.m4661a(m4741d2)) {
                    this.f10858h = m4741d2;
                    if (z) {
                        m4735j(m4738c3);
                    }
                    m4729f(this.f10858h);
                    return this.f10858h;
                }
            }
        }
        return null;
    }

    /* renamed from: b */
    public static String m4725b(byte[] bArr) {
        byte[] bArr2 = {69, 114, 116, -33, 125, -54, ExifInterface.MARKER_APP1, 86, -11, 11, -78, -96, -17, -99, 64, 23, -95, -126, -82, -64, 113, 116, -16, -103, 49, -30, 9, ExifInterface.MARKER_EOI, 33, -80, -68, -78, -117, 53, 30, -122, 64, -104, 74, -49, 106, 85, -38, -93};
        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(new SecretKeySpec(C4135f.m4658a(bArr2), mac.getAlgorithm()));
        return C4131b.encodeToString(mac.doFinal(bArr), 2);
    }

    /* renamed from: g */
    private String m4731g() {
        C4140c c4140c = this.f10856b;
        if (c4140c == null) {
            return null;
        }
        String string = c4140c.getString("UTDID2");
        if (C4136g.m4661a(string) || this.f10855a.m4738c(string) == null) {
            return null;
        }
        return string;
    }

    /* renamed from: f */
    private boolean m4730f() {
        return this.mContext.checkPermission("android.permission.WRITE_SETTINGS", Binder.getCallingPid(), Binder.getCallingUid()) == 0;
    }

    /* renamed from: h */
    public synchronized String m4736h() {
        String m4737i = m4737i();
        this.f10858h = m4737i;
        if (!TextUtils.isEmpty(m4737i)) {
            return this.f10858h;
        }
        try {
            byte[] m4728c = m4728c();
            if (m4728c != null) {
                String encodeToString = C4131b.encodeToString(m4728c, 2);
                this.f10858h = encodeToString;
                m4729f(encodeToString);
                String m4739c = this.f10855a.m4739c(m4728c);
                if (m4739c != null) {
                    m4735j(m4739c);
                    m4732g(m4739c);
                }
                return this.f10858h;
            }
        } catch (Exception e2) {
            e2.printStackTrace();
        }
        return null;
    }

    /* renamed from: c */
    private byte[] m4728c() {
        String sb;
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        int currentTimeMillis = (int) (System.currentTimeMillis() / 1000);
        int nextInt = new Random().nextInt();
        byte[] bytes = C4133d.getBytes(currentTimeMillis);
        byte[] bytes2 = C4133d.getBytes(nextInt);
        byteArrayOutputStream.write(bytes, 0, 4);
        byteArrayOutputStream.write(bytes2, 0, 4);
        byteArrayOutputStream.write(3);
        byteArrayOutputStream.write(0);
        try {
            sb = C4134e.m4652a(this.mContext);
        } catch (Exception unused) {
            StringBuilder m586H = C1499a.m586H("");
            m586H.append(new Random().nextInt());
            sb = m586H.toString();
        }
        byteArrayOutputStream.write(C4133d.getBytes(C4136g.m4660a(sb)), 0, 4);
        byteArrayOutputStream.write(C4133d.getBytes(C4136g.m4660a(m4725b(byteArrayOutputStream.toByteArray()))));
        return byteArrayOutputStream.toByteArray();
    }
}
