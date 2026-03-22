package com.alipay.android.phone.mrpc.core;

import android.text.format.Time;
import com.google.android.material.datepicker.UtcDates;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/* renamed from: com.alipay.android.phone.mrpc.core.k */
/* loaded from: classes.dex */
public final class C3151k {

    /* renamed from: a */
    private static final Pattern f8550a = Pattern.compile("([0-9]{1,2})[- ]([A-Za-z]{3,9})[- ]([0-9]{2,4})[ ]([0-9]{1,2}:[0-9][0-9]:[0-9][0-9])");

    /* renamed from: b */
    private static final Pattern f8551b = Pattern.compile("[ ]([A-Za-z]{3,9})[ ]+([0-9]{1,2})[ ]([0-9]{1,2}:[0-9][0-9]:[0-9][0-9])[ ]([0-9]{2,4})");

    /* renamed from: com.alipay.android.phone.mrpc.core.k$a */
    public static class a {

        /* renamed from: a */
        public int f8552a;

        /* renamed from: b */
        public int f8553b;

        /* renamed from: c */
        public int f8554c;

        public a(int i2, int i3, int i4) {
            this.f8552a = i2;
            this.f8553b = i3;
            this.f8554c = i4;
        }
    }

    /* renamed from: a */
    public static long m3676a(String str) {
        int m3678c;
        int m3679d;
        int i2;
        a aVar;
        int i3;
        int i4;
        int i5;
        Matcher matcher = f8550a.matcher(str);
        if (matcher.find()) {
            i2 = m3677b(matcher.group(1));
            m3678c = m3678c(matcher.group(2));
            m3679d = m3679d(matcher.group(3));
            aVar = m3680e(matcher.group(4));
        } else {
            Matcher matcher2 = f8551b.matcher(str);
            if (!matcher2.find()) {
                throw new IllegalArgumentException();
            }
            m3678c = m3678c(matcher2.group(1));
            int m3677b = m3677b(matcher2.group(2));
            a m3680e = m3680e(matcher2.group(3));
            m3679d = m3679d(matcher2.group(4));
            i2 = m3677b;
            aVar = m3680e;
        }
        if (m3679d >= 2038) {
            i3 = 1;
            i4 = 0;
            i5 = 2038;
        } else {
            i3 = i2;
            i4 = m3678c;
            i5 = m3679d;
        }
        Time time = new Time(UtcDates.UTC);
        time.set(aVar.f8554c, aVar.f8553b, aVar.f8552a, i3, i4, i5);
        return time.toMillis(false);
    }

    /* renamed from: b */
    private static int m3677b(String str) {
        if (str.length() != 2) {
            return str.charAt(0) - '0';
        }
        return (str.charAt(1) - '0') + ((str.charAt(0) - '0') * 10);
    }

    /* renamed from: c */
    private static int m3678c(String str) {
        int lowerCase = (Character.toLowerCase(str.charAt(2)) + (Character.toLowerCase(str.charAt(1)) + Character.toLowerCase(str.charAt(0)))) - 291;
        if (lowerCase == 9) {
            return 11;
        }
        if (lowerCase == 10) {
            return 1;
        }
        if (lowerCase == 22) {
            return 0;
        }
        if (lowerCase == 26) {
            return 7;
        }
        if (lowerCase == 29) {
            return 2;
        }
        if (lowerCase == 32) {
            return 3;
        }
        if (lowerCase == 40) {
            return 6;
        }
        if (lowerCase == 42) {
            return 5;
        }
        if (lowerCase == 48) {
            return 10;
        }
        switch (lowerCase) {
            case 35:
                return 9;
            case 36:
                return 4;
            case 37:
                return 8;
            default:
                throw new IllegalArgumentException();
        }
    }

    /* renamed from: d */
    private static int m3679d(String str) {
        if (str.length() == 2) {
            int charAt = (str.charAt(1) - '0') + ((str.charAt(0) - '0') * 10);
            return charAt >= 70 ? charAt + 1900 : charAt + 2000;
        }
        if (str.length() == 3) {
            return (str.charAt(2) - '0') + ((str.charAt(1) - '0') * 10) + ((str.charAt(0) - '0') * 100) + 1900;
        }
        if (str.length() == 4) {
            return (str.charAt(3) - '0') + ((str.charAt(2) - '0') * 10) + ((str.charAt(1) - '0') * 100) + ((str.charAt(0) - '0') * 1000);
        }
        return 1970;
    }

    /* renamed from: e */
    private static a m3680e(String str) {
        int i2;
        int charAt = str.charAt(0) - '0';
        if (str.charAt(1) != ':') {
            i2 = 2;
            charAt = (charAt * 10) + (str.charAt(1) - '0');
        } else {
            i2 = 1;
        }
        int i3 = i2 + 1 + 1 + 1 + 1;
        return new a(charAt, (str.charAt(r3) - '0') + ((str.charAt(r2) - '0') * 10), (str.charAt(i3 + 1) - '0') + ((str.charAt(i3) - '0') * 10));
    }
}
