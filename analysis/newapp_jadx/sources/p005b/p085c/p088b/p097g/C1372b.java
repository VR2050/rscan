package p005b.p085c.p088b.p097g;

import android.text.TextUtils;
import java.util.ArrayList;
import java.util.List;
import org.json.JSONObject;
import p005b.p085c.p088b.p098h.C1374b;
import p005b.p085c.p088b.p099i.C1375a;

/* renamed from: b.c.b.g.b */
/* loaded from: classes.dex */
public class C1372b {

    /* renamed from: a */
    public EnumC1371a f1245a;

    /* renamed from: b */
    public String[] f1246b;

    public C1372b(String str, EnumC1371a enumC1371a) {
        this.f1245a = enumC1371a;
    }

    /* renamed from: a */
    public static List<C1372b> m407a(JSONObject jSONObject) {
        EnumC1371a enumC1371a;
        String[] strArr;
        EnumC1371a enumC1371a2 = EnumC1371a.None;
        ArrayList arrayList = new ArrayList();
        if (jSONObject == null) {
            return arrayList;
        }
        String optString = jSONObject.optString("name", "");
        String[] split = !TextUtils.isEmpty(optString) ? optString.split(";") : null;
        for (int i2 = 0; i2 < split.length; i2++) {
            String str = split[i2];
            if (!TextUtils.isEmpty(str)) {
                EnumC1371a[] values = EnumC1371a.values();
                for (int i3 = 0; i3 < 6; i3++) {
                    enumC1371a = values[i3];
                    if (str.startsWith(enumC1371a.f1244k)) {
                        break;
                    }
                }
            }
            enumC1371a = enumC1371a2;
            if (enumC1371a != enumC1371a2) {
                C1372b c1372b = new C1372b(split[i2], enumC1371a);
                String str2 = split[i2];
                ArrayList arrayList2 = new ArrayList();
                int indexOf = str2.indexOf(40);
                int lastIndexOf = str2.lastIndexOf(41);
                if (indexOf == -1 || lastIndexOf == -1 || lastIndexOf <= indexOf) {
                    strArr = null;
                } else {
                    String[] split2 = str2.substring(indexOf + 1, lastIndexOf).split("' *, *'", -1);
                    for (String str3 : split2) {
                        arrayList2.add(str3.trim().replaceAll("'", "").replaceAll("\"", ""));
                    }
                    strArr = (String[]) arrayList2.toArray(new String[0]);
                }
                c1372b.f1246b = strArr;
                arrayList.add(c1372b);
            }
        }
        return arrayList;
    }

    /* renamed from: b */
    public static void m408b(C1372b c1372b) {
        String[] strArr = c1372b.f1246b;
        if (strArr.length == 3 && TextUtils.equals("tid", strArr[0])) {
            C1375a m420a = C1375a.m420a(C1374b.m417a().f1259b);
            if (TextUtils.isEmpty(strArr[1]) || TextUtils.isEmpty(strArr[2])) {
                return;
            }
            m420a.m421b(strArr[1], strArr[2]);
        }
    }
}
