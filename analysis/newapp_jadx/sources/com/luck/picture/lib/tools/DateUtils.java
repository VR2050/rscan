package com.luck.picture.lib.tools;

import java.text.SimpleDateFormat;
import java.util.Locale;
import java.util.concurrent.TimeUnit;
import p005b.p131d.p132a.p133a.C1499a;

/* loaded from: classes2.dex */
public class DateUtils {

    /* renamed from: sf */
    private static SimpleDateFormat f10212sf = new SimpleDateFormat("yyyyMMdd_HHmmssSS");

    public static String cdTime(long j2, long j3) {
        long j4 = j3 - j2;
        if (j4 > 1000) {
            return (j4 / 1000) + "秒";
        }
        return j4 + "毫秒";
    }

    public static int dateDiffer(long j2) {
        try {
            return (int) Math.abs(ValueOf.toLong(String.valueOf(System.currentTimeMillis()).substring(0, 10)) - j2);
        } catch (Exception e2) {
            e2.printStackTrace();
            return -1;
        }
    }

    public static String formatDurationTime(long j2) {
        Locale locale = Locale.getDefault();
        TimeUnit timeUnit = TimeUnit.MILLISECONDS;
        return String.format(locale, "%02d:%02d", Long.valueOf(timeUnit.toMinutes(j2)), Long.valueOf(timeUnit.toSeconds(j2) - TimeUnit.MINUTES.toSeconds(timeUnit.toMinutes(j2))));
    }

    public static String getCreateFileName(String str) {
        long currentTimeMillis = System.currentTimeMillis();
        StringBuilder m586H = C1499a.m586H(str);
        m586H.append(f10212sf.format(Long.valueOf(currentTimeMillis)));
        return m586H.toString();
    }

    public static String getCreateFileName() {
        return f10212sf.format(Long.valueOf(System.currentTimeMillis()));
    }
}
