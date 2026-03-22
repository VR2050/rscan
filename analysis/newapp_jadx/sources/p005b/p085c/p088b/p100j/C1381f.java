package p005b.p085c.p088b.p100j;

import android.content.Context;
import android.text.TextUtils;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import p005b.p085c.p088b.p089a.EnumC1350g;
import p005b.p085c.p088b.p089a.p090h.C1353c;
import p005b.p085c.p088b.p098h.C1373a;
import p005b.p131d.p132a.p133a.C1499a;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.c.b.j.f */
/* loaded from: classes.dex */
public class C1381f {
    /* renamed from: a */
    public static String m429a(String str) {
        String str2 = null;
        if (TextUtils.isEmpty(str)) {
            return null;
        }
        String[] split = str.split(";");
        for (int i2 = 0; i2 < split.length; i2++) {
            if (split[i2].startsWith("result={") && split[i2].endsWith("}")) {
                String[] split2 = split[i2].substring(8, split[i2].length() - 1).split("&");
                int i3 = 0;
                while (true) {
                    if (i3 >= split2.length) {
                        break;
                    }
                    if (split2[i3].startsWith("trade_token=\"") && split2[i3].endsWith("\"")) {
                        str2 = split2[i3].substring(13, split2[i3].length() - 1);
                        break;
                    }
                    if (split2[i3].startsWith("trade_token=")) {
                        str2 = split2[i3].substring(12);
                        break;
                    }
                    i3++;
                }
            }
        }
        return str2;
    }

    /* renamed from: b */
    public static String m430b(String str, String str2) {
        try {
            Matcher matcher = Pattern.compile("(^|;)" + str2 + "=\\{([^}]*?)\\}").matcher(str);
            if (matcher.find()) {
                return matcher.group(2);
            }
        } catch (Throwable th) {
            C4195m.m4816l(th);
        }
        return "?";
    }

    /* renamed from: c */
    public static Map<String, String> m431c(C1373a c1373a, String str) {
        EnumC1350g m358a = EnumC1350g.m358a(6001);
        HashMap hashMap = new HashMap();
        hashMap.put("resultStatus", Integer.toString(m358a.f1179l));
        hashMap.put("memo", m358a.f1180m);
        hashMap.put("result", "");
        try {
            return m432d(str);
        } catch (Throwable th) {
            C1353c.m363d(c1373a, "biz", "FormatResultEx", th);
            return hashMap;
        }
    }

    /* renamed from: d */
    public static Map<String, String> m432d(String str) {
        String[] split = str.split(";");
        HashMap hashMap = new HashMap();
        for (String str2 : split) {
            String substring = str2.substring(0, str2.indexOf("={"));
            String m637w = C1499a.m637w(substring, "={");
            hashMap.put(substring, str2.substring(m637w.length() + str2.indexOf(m637w), str2.lastIndexOf("}")));
        }
        return hashMap;
    }

    /* renamed from: e */
    public static void m433e(C1373a c1373a, Context context, String str) {
        try {
            String m429a = m429a(str);
            C4195m.m4787T("mspl", "trade token: " + m429a);
            if (TextUtils.isEmpty(m429a)) {
                return;
            }
            C1382g.m435b(c1373a, context, "pref_trade_token", m429a);
        } catch (Throwable th) {
            C1353c.m363d(c1373a, "biz", "SaveTradeTokenError", th);
            C4195m.m4816l(th);
        }
    }
}
