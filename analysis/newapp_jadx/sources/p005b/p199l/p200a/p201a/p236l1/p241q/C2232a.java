package p005b.p199l.p200a.p201a.p236l1.p241q;

import android.text.Html;
import android.text.Spanned;
import android.text.TextUtils;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import p005b.p199l.p200a.p201a.p236l1.AbstractC2208c;
import p005b.p199l.p200a.p201a.p236l1.C2207b;
import p005b.p199l.p200a.p201a.p236l1.InterfaceC2210e;
import p005b.p199l.p200a.p201a.p250p1.C2360t;

/* renamed from: b.l.a.a.l1.q.a */
/* loaded from: classes.dex */
public final class C2232a extends AbstractC2208c {

    /* renamed from: n */
    public static final Pattern f5486n = Pattern.compile("\\s*((?:(\\d+):)?(\\d+):(\\d+),(\\d+))\\s*-->\\s*((?:(\\d+):)?(\\d+):(\\d+),(\\d+))\\s*");

    /* renamed from: o */
    public static final Pattern f5487o = Pattern.compile("\\{\\\\.*?\\}");

    /* renamed from: p */
    public final StringBuilder f5488p;

    /* renamed from: q */
    public final ArrayList<String> f5489q;

    public C2232a() {
        super("SubripDecoder");
        this.f5488p = new StringBuilder();
        this.f5489q = new ArrayList<>();
    }

    /* renamed from: k */
    public static float m2096k(int i2) {
        if (i2 == 0) {
            return 0.08f;
        }
        if (i2 == 1) {
            return 0.5f;
        }
        if (i2 == 2) {
            return 0.92f;
        }
        throw new IllegalArgumentException();
    }

    /* renamed from: l */
    public static long m2097l(Matcher matcher, int i2) {
        return (Long.parseLong(matcher.group(i2 + 4)) + (Long.parseLong(matcher.group(i2 + 3)) * 1000) + (Long.parseLong(matcher.group(i2 + 2)) * 60 * 1000) + (Long.parseLong(matcher.group(i2 + 1)) * 60 * 60 * 1000)) * 1000;
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue */
    @Override // p005b.p199l.p200a.p201a.p236l1.AbstractC2208c
    /* renamed from: j */
    public InterfaceC2210e mo2047j(byte[] bArr, int i2, boolean z) {
        C2360t c2360t;
        String m2574f;
        long[] jArr;
        char c2;
        char c3;
        C2207b c2207b;
        C2232a c2232a = this;
        ArrayList arrayList = new ArrayList();
        long[] jArr2 = new long[32];
        C2360t c2360t2 = new C2360t(bArr, i2);
        int i3 = 0;
        int i4 = 0;
        while (true) {
            String m2574f2 = c2360t2.m2574f();
            if (m2574f2 != null) {
                if (m2574f2.length() != 0) {
                    try {
                        Integer.parseInt(m2574f2);
                        m2574f = c2360t2.m2574f();
                    } catch (NumberFormatException unused) {
                    }
                    if (m2574f != null) {
                        Matcher matcher = f5486n.matcher(m2574f);
                        if (matcher.matches()) {
                            long m2097l = m2097l(matcher, 1);
                            if (i4 == jArr2.length) {
                                jArr2 = Arrays.copyOf(jArr2, i4 * 2);
                            }
                            int i5 = i4 + 1;
                            jArr2[i4] = m2097l;
                            long m2097l2 = m2097l(matcher, 6);
                            if (i5 == jArr2.length) {
                                jArr2 = Arrays.copyOf(jArr2, i5 * 2);
                            }
                            int i6 = i5 + 1;
                            jArr2[i5] = m2097l2;
                            c2232a.f5488p.setLength(i3);
                            c2232a.f5489q.clear();
                            for (String m2574f3 = c2360t2.m2574f(); !TextUtils.isEmpty(m2574f3); m2574f3 = c2360t2.m2574f()) {
                                if (c2232a.f5488p.length() > 0) {
                                    c2232a.f5488p.append("<br>");
                                }
                                StringBuilder sb = c2232a.f5488p;
                                ArrayList<String> arrayList2 = c2232a.f5489q;
                                String trim = m2574f3.trim();
                                StringBuilder sb2 = new StringBuilder(trim);
                                Matcher matcher2 = f5487o.matcher(trim);
                                int i7 = 0;
                                while (matcher2.find()) {
                                    String group = matcher2.group();
                                    arrayList2.add(group);
                                    int start = matcher2.start() - i7;
                                    int length = group.length();
                                    sb2.replace(start, start + length, "");
                                    i7 += length;
                                }
                                sb.append(sb2.toString());
                            }
                            Spanned fromHtml = Html.fromHtml(c2232a.f5488p.toString());
                            String str = null;
                            int i8 = 0;
                            while (true) {
                                if (i8 < c2232a.f5489q.size()) {
                                    String str2 = c2232a.f5489q.get(i8);
                                    if (str2.matches("\\{\\\\an[1-9]\\}")) {
                                        str = str2;
                                    } else {
                                        i8++;
                                    }
                                }
                            }
                            if (str == null) {
                                c2207b = new C2207b(fromHtml);
                                jArr = jArr2;
                                c2360t = c2360t2;
                            } else {
                                jArr = jArr2;
                                switch (str.hashCode()) {
                                    case -685620710:
                                        if (str.equals("{\\an1}")) {
                                            c2 = 0;
                                            break;
                                        }
                                        c2 = 65535;
                                        break;
                                    case -685620679:
                                        if (str.equals("{\\an2}")) {
                                            c2 = 6;
                                            break;
                                        }
                                        c2 = 65535;
                                        break;
                                    case -685620648:
                                        if (str.equals("{\\an3}")) {
                                            c2 = 3;
                                            break;
                                        }
                                        c2 = 65535;
                                        break;
                                    case -685620617:
                                        if (str.equals("{\\an4}")) {
                                            c2 = 1;
                                            break;
                                        }
                                        c2 = 65535;
                                        break;
                                    case -685620586:
                                        if (str.equals("{\\an5}")) {
                                            c2 = 7;
                                            break;
                                        }
                                        c2 = 65535;
                                        break;
                                    case -685620555:
                                        if (str.equals("{\\an6}")) {
                                            c2 = 4;
                                            break;
                                        }
                                        c2 = 65535;
                                        break;
                                    case -685620524:
                                        if (str.equals("{\\an7}")) {
                                            c2 = 2;
                                            break;
                                        }
                                        c2 = 65535;
                                        break;
                                    case -685620493:
                                        if (str.equals("{\\an8}")) {
                                            c2 = '\b';
                                            break;
                                        }
                                        c2 = 65535;
                                        break;
                                    case -685620462:
                                        if (str.equals("{\\an9}")) {
                                            c2 = 5;
                                            break;
                                        }
                                        c2 = 65535;
                                        break;
                                    default:
                                        c2 = 65535;
                                        break;
                                }
                                c2360t = c2360t2;
                                int i9 = (c2 == 0 || c2 == 1 || c2 == 2) ? 0 : (c2 == 3 || c2 == 4 || c2 == 5) ? 2 : 1;
                                switch (str.hashCode()) {
                                    case -685620710:
                                        if (str.equals("{\\an1}")) {
                                            c3 = 0;
                                            break;
                                        }
                                        c3 = 65535;
                                        break;
                                    case -685620679:
                                        if (str.equals("{\\an2}")) {
                                            c3 = 1;
                                            break;
                                        }
                                        c3 = 65535;
                                        break;
                                    case -685620648:
                                        if (str.equals("{\\an3}")) {
                                            c3 = 2;
                                            break;
                                        }
                                        c3 = 65535;
                                        break;
                                    case -685620617:
                                        if (str.equals("{\\an4}")) {
                                            c3 = 6;
                                            break;
                                        }
                                        c3 = 65535;
                                        break;
                                    case -685620586:
                                        if (str.equals("{\\an5}")) {
                                            c3 = 7;
                                            break;
                                        }
                                        c3 = 65535;
                                        break;
                                    case -685620555:
                                        if (str.equals("{\\an6}")) {
                                            c3 = '\b';
                                            break;
                                        }
                                        c3 = 65535;
                                        break;
                                    case -685620524:
                                        if (str.equals("{\\an7}")) {
                                            c3 = 3;
                                            break;
                                        }
                                        c3 = 65535;
                                        break;
                                    case -685620493:
                                        if (str.equals("{\\an8}")) {
                                            c3 = 4;
                                            break;
                                        }
                                        c3 = 65535;
                                        break;
                                    case -685620462:
                                        if (str.equals("{\\an9}")) {
                                            c3 = 5;
                                            break;
                                        }
                                        c3 = 65535;
                                        break;
                                    default:
                                        c3 = 65535;
                                        break;
                                }
                                int i10 = (c3 == 0 || c3 == 1 || c3 == 2) ? 2 : (c3 == 3 || c3 == 4 || c3 == 5) ? 0 : 1;
                                c2207b = new C2207b(fromHtml, null, m2096k(i10), 0, i10, m2096k(i9), i9, -3.4028235E38f);
                            }
                            arrayList.add(c2207b);
                            arrayList.add(C2207b.f5274c);
                            c2232a = this;
                            i4 = i6;
                            jArr2 = jArr;
                            c2360t2 = c2360t;
                            i3 = 0;
                        }
                        c2360t = c2360t2;
                        c2232a = this;
                        c2360t2 = c2360t;
                        i3 = 0;
                    }
                }
            }
        }
        C2207b[] c2207bArr = new C2207b[arrayList.size()];
        arrayList.toArray(c2207bArr);
        return new C2233b(c2207bArr, Arrays.copyOf(jArr2, i4));
    }
}
