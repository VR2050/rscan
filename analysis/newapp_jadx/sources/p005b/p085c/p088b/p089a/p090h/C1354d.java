package p005b.p085c.p088b.p089a.p090h;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.Signature;
import android.os.Build;
import android.text.TextUtils;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.Objects;
import java.util.UUID;
import net.sourceforge.pinyin4j.ChineseToPinyinResource;
import org.json.JSONObject;
import p005b.p085c.p088b.p089a.p090h.C1353c;
import p005b.p085c.p088b.p098h.C1374b;
import p005b.p085c.p088b.p099i.C1375a;
import p005b.p085c.p088b.p100j.C1377b;
import p005b.p085c.p088b.p100j.C1382g;
import p005b.p085c.p088b.p100j.C1383h;
import p005b.p131d.p132a.p133a.C1499a;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.c.b.a.h.d */
/* loaded from: classes.dex */
public class C1354d {

    /* renamed from: a */
    public String f1184a;

    /* renamed from: b */
    public String f1185b;

    /* renamed from: c */
    public String f1186c;

    /* renamed from: d */
    public String f1187d;

    /* renamed from: e */
    public String f1188e;

    /* renamed from: f */
    public String f1189f;

    /* renamed from: g */
    public String f1190g;

    /* renamed from: h */
    public String f1191h = "";

    /* renamed from: i */
    public String f1192i = "";

    /* renamed from: j */
    public String f1193j;

    public C1354d(Context context, boolean z) {
        String str;
        String str2;
        String str3;
        context = context != null ? context.getApplicationContext() : context;
        String format = new SimpleDateFormat("yyyy-MM-dd-HH:mm:ss").format(new Date());
        Object[] objArr = new Object[2];
        try {
            str = UUID.randomUUID().toString();
        } catch (Throwable unused) {
            str = "12345678uuid";
        }
        objArr[0] = str;
        objArr[1] = format;
        this.f1184a = String.format("%s,%s", objArr);
        String str4 = "-";
        if (context != null) {
            try {
                Context applicationContext = context.getApplicationContext();
                str2 = applicationContext.getPackageName();
                try {
                    PackageInfo packageInfo = applicationContext.getPackageManager().getPackageInfo(str2, 64);
                    str4 = packageInfo.versionName + "|" + m370a(packageInfo);
                } catch (Throwable unused2) {
                }
            } catch (Throwable unused3) {
                str2 = "-";
            }
            str3 = str4;
            str4 = str2;
        } else {
            str3 = "-";
        }
        this.f1186c = String.format("%s,%s,-,-,-", m372d(str4), m372d(str3));
        long j2 = 0;
        if (!z) {
            synchronized (C1353c.b.class) {
                try {
                    String m436c = C1382g.m436c(null, context, "alipay_cashier_statistic_v", null);
                    if (!TextUtils.isEmpty(m436c)) {
                        j2 = Long.parseLong(m436c);
                    }
                } catch (Throwable unused4) {
                }
                j2++;
                try {
                    C1382g.m435b(null, context, "alipay_cashier_statistic_v", Long.toString(j2));
                } catch (Throwable unused5) {
                }
            }
        }
        this.f1187d = String.format("android,3,%s,%s,com.alipay.mcpay,5.0,-,%s,-", m372d("15.7.7"), m372d("h.a.3.7.7"), C1499a.m630p("~", j2));
        this.f1188e = String.format("%s,%s,-,-,-", m372d(C1375a.m420a(C1374b.m417a().f1259b).f1262c), m372d(C1374b.m417a().m419c()));
        String str5 = "";
        if (context != null) {
            try {
                str5 = context.getResources().getConfiguration().locale.toString();
            } catch (Throwable unused6) {
            }
        }
        String m372d = m372d(str5);
        String m372d2 = m372d(Build.VERSION.RELEASE);
        String m372d3 = m372d(Build.MODEL);
        Objects.requireNonNull(C1377b.m424a(context));
        String m372d4 = m372d("000000000000000");
        String m372d5 = m372d(C1377b.m425b(context).f1290v);
        Objects.requireNonNull(C1377b.m424a(context));
        this.f1189f = String.format("%s,%s,%s,%s,%s,%s,%s,%s,%s,-", m372d, "android", m372d2, m372d3, "-", m372d4, m372d5, "gw", m372d("000000000000000"));
        this.f1190g = "-";
        this.f1193j = "-";
    }

    /* renamed from: a */
    public static String m370a(PackageInfo packageInfo) {
        String str;
        String m440d;
        Signature[] signatureArr = packageInfo.signatures;
        if (signatureArr == null || signatureArr.length == 0) {
            return "0";
        }
        try {
            StringBuilder sb = new StringBuilder();
            sb.append(packageInfo.signatures.length);
            for (Signature signature : packageInfo.signatures) {
                try {
                    m440d = C1383h.m440d(null, signature.toByteArray());
                } catch (Throwable unused) {
                }
                if (TextUtils.isEmpty(m440d)) {
                    str = "?";
                    sb.append("-");
                    sb.append(str);
                } else {
                    str = C1383h.m452p(m440d).substring(0, 8);
                    sb.append("-");
                    sb.append(str);
                }
            }
            return sb.toString();
        } catch (Throwable unused2) {
            return "?";
        }
    }

    /* renamed from: c */
    public static String m371c(Throwable th) {
        if (th == null) {
            return "";
        }
        StringBuffer stringBuffer = new StringBuffer();
        try {
            stringBuffer.append(th.getClass().getName());
            stringBuffer.append(":");
            stringBuffer.append(th.getMessage());
            stringBuffer.append(" 》 ");
            StackTraceElement[] stackTrace = th.getStackTrace();
            if (stackTrace != null) {
                int i2 = 0;
                for (StackTraceElement stackTraceElement : stackTrace) {
                    stringBuffer.append(stackTraceElement.toString());
                    stringBuffer.append(" 》 ");
                    i2++;
                    if (i2 > 5) {
                        break;
                    }
                }
            }
        } catch (Throwable unused) {
        }
        return stringBuffer.toString();
    }

    /* renamed from: d */
    public static String m372d(String str) {
        return TextUtils.isEmpty(str) ? "" : str.replace("[", "【").replace("]", "】").replace(ChineseToPinyinResource.Field.LEFT_BRACKET, "（").replace(ChineseToPinyinResource.Field.RIGHT_BRACKET, "）").replace(ChineseToPinyinResource.Field.COMMA, "，").replace("^", "~").replace("#", "＃");
    }

    /* renamed from: b */
    public String m373b(String str) {
        String str2;
        String str3;
        String[] split = (str == null ? "" : str).split("&");
        String str4 = null;
        int i2 = 2;
        if (split != null) {
            int length = split.length;
            String str5 = null;
            str2 = null;
            str3 = null;
            int i3 = 0;
            while (i3 < length) {
                String[] split2 = split[i3].split("=");
                if (split2 != null && split2.length == i2) {
                    if (split2[0].equalsIgnoreCase("partner")) {
                        str2 = split2[1].replace("\"", "");
                    } else if (split2[0].equalsIgnoreCase("out_trade_no")) {
                        str3 = split2[1].replace("\"", "");
                    } else if (split2[0].equalsIgnoreCase("trade_no")) {
                        str5 = split2[1].replace("\"", "");
                    } else if (split2[0].equalsIgnoreCase("biz_content")) {
                        try {
                            JSONObject jSONObject = new JSONObject(C1383h.m444h(null, split2[1]));
                            if (TextUtils.isEmpty(str3)) {
                                str3 = jSONObject.getString("out_trade_no");
                            }
                        } catch (Throwable unused) {
                        }
                    } else if (split2[0].equalsIgnoreCase("app_id") && TextUtils.isEmpty(str2)) {
                        str2 = split2[1];
                    }
                }
                i3++;
                i2 = 2;
            }
            str4 = str5;
        } else {
            str2 = null;
            str3 = null;
        }
        String format = String.format("%s,%s,-,%s,-,-,-", m372d(str4), m372d(str3), m372d(str2));
        this.f1185b = format;
        Object[] objArr = new Object[10];
        objArr[0] = this.f1184a;
        objArr[1] = format;
        objArr[2] = this.f1186c;
        objArr[3] = this.f1187d;
        objArr[4] = this.f1188e;
        objArr[5] = this.f1189f;
        objArr[6] = this.f1190g;
        String str6 = this.f1191h;
        if (TextUtils.isEmpty(str6)) {
            str6 = "-";
        }
        objArr[7] = str6;
        String str7 = this.f1192i;
        objArr[8] = TextUtils.isEmpty(str7) ? "-" : str7;
        objArr[9] = this.f1193j;
        return String.format("[(%s),(%s),(%s),(%s),(%s),(%s),(%s),(%s),(%s),(%s)]", objArr);
    }

    /* renamed from: e */
    public final synchronized void m374e(String str, String str2, String str3) {
        C4195m.m4787T("mspl", String.format("err %s %s %s", str, str2, str3));
        String str4 = TextUtils.isEmpty(this.f1192i) ? "" : "^";
        StringBuilder sb = new StringBuilder();
        sb.append(str4);
        Object[] objArr = new Object[4];
        objArr[0] = str;
        objArr[1] = str2;
        objArr[2] = TextUtils.isEmpty(str3) ? "-" : m372d(str3);
        objArr[3] = m372d(new SimpleDateFormat("HH:mm:ss:SSS", Locale.getDefault()).format(new Date()));
        sb.append(String.format("%s,%s,%s,%s", objArr));
        this.f1192i += sb.toString();
    }

    /* renamed from: f */
    public final synchronized void m375f(String str, String str2, String str3) {
        C4195m.m4787T("mspl", String.format("event %s %s %s", str, str2, str3));
        String str4 = TextUtils.isEmpty(this.f1191h) ? "" : "^";
        StringBuilder sb = new StringBuilder();
        sb.append(str4);
        Object[] objArr = new Object[4];
        objArr[0] = TextUtils.isEmpty(str) ? "-" : m372d(str);
        objArr[1] = m372d(str2);
        objArr[2] = m372d(str3);
        objArr[3] = m372d(new SimpleDateFormat("HH:mm:ss:SSS", Locale.getDefault()).format(new Date()));
        sb.append(String.format("%s,%s,%s,-,-,-,-,-,-,-,-,-,-,%s", objArr));
        this.f1191h += sb.toString();
    }
}
