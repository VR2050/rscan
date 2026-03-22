package p005b.p199l.p200a.p201a.p236l1.p244t;

import java.util.regex.Pattern;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.C2205l0;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;
import p005b.p199l.p200a.p201a.p250p1.C2360t;

/* renamed from: b.l.a.a.l1.t.h */
/* loaded from: classes.dex */
public final class C2248h {

    /* renamed from: a */
    public static final Pattern f5602a = Pattern.compile("^NOTE([ \t].*)?$");

    /* renamed from: a */
    public static boolean m2135a(C2360t c2360t) {
        String m2574f = c2360t.m2574f();
        return m2574f != null && m2574f.startsWith("WEBVTT");
    }

    /* renamed from: b */
    public static float m2136b(String str) {
        if (str.endsWith("%")) {
            return Float.parseFloat(str.substring(0, str.length() - 1)) / 100.0f;
        }
        throw new NumberFormatException("Percentages must end with %");
    }

    /* renamed from: c */
    public static long m2137c(String str) {
        int i2 = C2344d0.f6035a;
        String[] split = str.split("\\.", 2);
        long j2 = 0;
        for (String str2 : C2344d0.m2316H(split[0], ":")) {
            j2 = (j2 * 60) + Long.parseLong(str2);
        }
        long j3 = j2 * 1000;
        if (split.length == 2) {
            j3 += Long.parseLong(split[1]);
        }
        return j3 * 1000;
    }

    /* renamed from: d */
    public static void m2138d(C2360t c2360t) {
        int i2 = c2360t.f6134b;
        if (m2135a(c2360t)) {
            return;
        }
        c2360t.m2567C(i2);
        StringBuilder m586H = C1499a.m586H("Expected WEBVTT. Got ");
        m586H.append(c2360t.m2574f());
        throw new C2205l0(m586H.toString());
    }
}
