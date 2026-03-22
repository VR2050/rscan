package com.alipay.apmobilesecuritysdk.p390c;

import android.content.Context;
import android.os.Build;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import p005b.p085c.p102c.p103a.p104a.p109d.C1398a;
import p005b.p085c.p102c.p103a.p104a.p109d.C1401d;

/* renamed from: com.alipay.apmobilesecuritysdk.c.a */
/* loaded from: classes.dex */
public final class C3169a {
    /* renamed from: a */
    public static synchronized void m3738a(Context context, String str, String str2, String str3) {
        synchronized (C3169a.class) {
            C1398a m3741b = m3741b(context, str, str2, str3);
            String str4 = context.getFilesDir().getAbsolutePath() + "/log/ap";
            String str5 = new SimpleDateFormat("yyyyMMdd").format(Calendar.getInstance().getTime()) + ".log";
            String c1398a = m3741b.toString();
            synchronized (C1401d.class) {
                C1401d.f1332a = str4;
                C1401d.f1333b = str5;
                C1401d.f1334c = c1398a;
            }
        }
    }

    /* renamed from: a */
    public static synchronized void m3740a(Throwable th) {
        synchronized (C3169a.class) {
            C1401d.m480a(th);
        }
    }

    /* renamed from: b */
    private static C1398a m3741b(Context context, String str, String str2, String str3) {
        String str4;
        try {
            str4 = context.getPackageName();
        } catch (Throwable unused) {
            str4 = "";
        }
        return new C1398a(Build.MODEL, str4, "APPSecuritySDK-ALIPAYSDK", "3.4.0.201910161639", str, str2, str3);
    }

    /* renamed from: a */
    public static synchronized void m3739a(String str) {
        synchronized (C3169a.class) {
            synchronized (C1401d.class) {
                ArrayList arrayList = new ArrayList();
                arrayList.add(str);
                C1401d.m481b(arrayList);
            }
        }
    }
}
