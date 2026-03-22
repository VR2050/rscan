package p005b.p085c.p102c.p103a.p104a.p109d;

import android.os.Build;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import net.sourceforge.pinyin4j.ChineseToPinyinResource;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.c.c.a.a.d.a */
/* loaded from: classes.dex */
public final class C1398a {

    /* renamed from: a */
    public String f1325a;

    /* renamed from: b */
    public String f1326b;

    /* renamed from: c */
    public String f1327c;

    /* renamed from: d */
    public String f1328d;

    public C1398a(String str, String str2, String str3, String str4, String str5, String str6, String str7) {
        this.f1325a = str2;
        this.f1326b = str5;
        this.f1327c = str6;
        this.f1328d = str7;
    }

    public final String toString() {
        StringBuilder sb;
        String str;
        StringBuilder sb2;
        String str2;
        StringBuilder sb3;
        String str3;
        StringBuffer stringBuffer = new StringBuffer(new SimpleDateFormat("yyyyMMddHHmmssSSS").format(Calendar.getInstance().getTime()));
        stringBuffer.append(ChineseToPinyinResource.Field.COMMA + Build.MODEL);
        stringBuffer.append(ChineseToPinyinResource.Field.COMMA + this.f1325a);
        stringBuffer.append(",APPSecuritySDK-ALIPAYSDK");
        stringBuffer.append(",3.4.0.201910161639");
        if (C4195m.m4822o(this.f1326b) || this.f1326b.length() < 20) {
            sb = new StringBuilder(ChineseToPinyinResource.Field.COMMA);
            str = this.f1326b;
        } else {
            sb = new StringBuilder(ChineseToPinyinResource.Field.COMMA);
            str = this.f1326b.substring(0, 20);
        }
        sb.append(str);
        stringBuffer.append(sb.toString());
        if (C4195m.m4822o(this.f1327c) || this.f1327c.length() < 20) {
            sb2 = new StringBuilder(ChineseToPinyinResource.Field.COMMA);
            str2 = this.f1327c;
        } else {
            sb2 = new StringBuilder(ChineseToPinyinResource.Field.COMMA);
            str2 = this.f1327c.substring(0, 20);
        }
        sb2.append(str2);
        stringBuffer.append(sb2.toString());
        if (C4195m.m4822o(this.f1328d) || this.f1328d.length() < 20) {
            sb3 = new StringBuilder(ChineseToPinyinResource.Field.COMMA);
            str3 = this.f1328d;
        } else {
            sb3 = new StringBuilder(ChineseToPinyinResource.Field.COMMA);
            str3 = this.f1328d.substring(0, 20);
        }
        sb3.append(str3);
        stringBuffer.append(sb3.toString());
        return stringBuffer.toString();
    }
}
