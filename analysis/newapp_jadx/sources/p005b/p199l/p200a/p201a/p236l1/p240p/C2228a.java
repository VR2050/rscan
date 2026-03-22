package p005b.p199l.p200a.p201a.p236l1.p240p;

import android.graphics.PointF;
import android.text.Layout;
import androidx.annotation.Nullable;
import androidx.work.WorkRequest;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import net.sourceforge.pinyin4j.ChineseToPinyinResource;
import p005b.p199l.p200a.p201a.p236l1.AbstractC2208c;
import p005b.p199l.p200a.p201a.p236l1.C2207b;
import p005b.p199l.p200a.p201a.p236l1.InterfaceC2210e;
import p005b.p199l.p200a.p201a.p236l1.p240p.C2230c;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;
import p005b.p199l.p200a.p201a.p250p1.C2360t;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.l.a.a.l1.p.a */
/* loaded from: classes.dex */
public final class C2228a extends AbstractC2208c {

    /* renamed from: n */
    public static final Pattern f5464n = Pattern.compile("(?:(\\d+):)?(\\d+):(\\d+)[:.](\\d+)");

    /* renamed from: o */
    public final boolean f5465o;

    /* renamed from: p */
    @Nullable
    public final C2229b f5466p;

    /* renamed from: q */
    public Map<String, C2230c> f5467q;

    /* renamed from: r */
    public float f5468r;

    /* renamed from: s */
    public float f5469s;

    public C2228a(@Nullable List<byte[]> list) {
        super("SsaDecoder");
        this.f5468r = -3.4028235E38f;
        this.f5469s = -3.4028235E38f;
        if (list == null || list.isEmpty()) {
            this.f5465o = false;
            this.f5466p = null;
            return;
        }
        this.f5465o = true;
        byte[] bArr = list.get(0);
        int i2 = C2344d0.f6035a;
        String str = new String(bArr, Charset.forName("UTF-8"));
        C4195m.m4765F(str.startsWith("Format:"));
        C2229b m2093a = C2229b.m2093a(str);
        Objects.requireNonNull(m2093a);
        this.f5466p = m2093a;
        m2092m(new C2360t(list.get(1)));
    }

    /* renamed from: k */
    public static int m2089k(long j2, List<Long> list, List<List<C2207b>> list2) {
        int i2;
        int size = list.size() - 1;
        while (true) {
            if (size < 0) {
                i2 = 0;
                break;
            }
            if (list.get(size).longValue() == j2) {
                return size;
            }
            if (list.get(size).longValue() < j2) {
                i2 = size + 1;
                break;
            }
            size--;
        }
        list.add(i2, Long.valueOf(j2));
        list2.add(i2, i2 == 0 ? new ArrayList() : new ArrayList(list2.get(i2 - 1)));
        return i2;
    }

    /* renamed from: l */
    public static float m2090l(int i2) {
        if (i2 == 0) {
            return 0.05f;
        }
        if (i2 != 1) {
            return i2 != 2 ? -3.4028235E38f : 0.95f;
        }
        return 0.5f;
    }

    /* renamed from: n */
    public static long m2091n(String str) {
        Matcher matcher = f5464n.matcher(str.trim());
        if (!matcher.matches()) {
            return -9223372036854775807L;
        }
        String group = matcher.group(1);
        int i2 = C2344d0.f6035a;
        return (Long.parseLong(matcher.group(4)) * WorkRequest.MIN_BACKOFF_MILLIS) + (Long.parseLong(matcher.group(3)) * 1000000) + (Long.parseLong(matcher.group(2)) * 60 * 1000000) + (Long.parseLong(group) * 60 * 60 * 1000000);
    }

    @Override // p005b.p199l.p200a.p201a.p236l1.AbstractC2208c
    /* renamed from: j */
    public InterfaceC2210e mo2047j(byte[] bArr, int i2, boolean z) {
        int i3;
        int i4;
        float m2090l;
        float m2090l2;
        Layout.Alignment alignment;
        Layout.Alignment alignment2;
        int m2094a;
        int i5;
        ArrayList arrayList = new ArrayList();
        ArrayList arrayList2 = new ArrayList();
        C2360t c2360t = new C2360t(bArr, i2);
        if (!this.f5465o) {
            m2092m(c2360t);
        }
        C2229b c2229b = this.f5465o ? this.f5466p : null;
        while (true) {
            String m2574f = c2360t.m2574f();
            if (m2574f == null) {
                return new C2231d(arrayList, arrayList2);
            }
            if (m2574f.startsWith("Format:")) {
                c2229b = C2229b.m2093a(m2574f);
            } else if (m2574f.startsWith("Dialogue:") && c2229b != null) {
                C4195m.m4765F(m2574f.startsWith("Dialogue:"));
                String[] split = m2574f.substring(9).split(ChineseToPinyinResource.Field.COMMA, c2229b.f5474e);
                if (split.length == c2229b.f5474e) {
                    long m2091n = m2091n(split[c2229b.f5470a]);
                    if (m2091n != -9223372036854775807L) {
                        long m2091n2 = m2091n(split[c2229b.f5471b]);
                        if (m2091n2 != -9223372036854775807L) {
                            Map<String, C2230c> map = this.f5467q;
                            C2230c c2230c = (map == null || (i5 = c2229b.f5472c) == -1) ? null : map.get(split[i5].trim());
                            String str = split[c2229b.f5473d];
                            Matcher matcher = C2230c.b.f5480a.matcher(str);
                            int i6 = -1;
                            PointF pointF = null;
                            while (matcher.find()) {
                                String group = matcher.group(1);
                                try {
                                    PointF m2095a = C2230c.b.m2095a(group);
                                    if (m2095a != null) {
                                        pointF = m2095a;
                                    }
                                } catch (RuntimeException unused) {
                                }
                                try {
                                    Matcher matcher2 = C2230c.b.f5483d.matcher(group);
                                    m2094a = matcher2.find() ? C2230c.m2094a(matcher2.group(1)) : -1;
                                } catch (RuntimeException unused2) {
                                }
                                if (m2094a != -1) {
                                    i6 = m2094a;
                                }
                            }
                            String replaceAll = C2230c.b.f5480a.matcher(str).replaceAll("").replaceAll("\\\\N", "\n").replaceAll("\\\\n", "\n");
                            float f2 = this.f5468r;
                            float f3 = this.f5469s;
                            int i7 = -1;
                            if (i6 != -1) {
                                i7 = i6;
                            } else if (c2230c != null) {
                                i7 = c2230c.f5476b;
                            }
                            switch (i7) {
                                case 1:
                                case 4:
                                case 7:
                                    i3 = 0;
                                    break;
                                case 2:
                                case 5:
                                case 8:
                                    i3 = 1;
                                    break;
                                case 3:
                                case 6:
                                case 9:
                                    i3 = 2;
                                    break;
                                default:
                                    i3 = Integer.MIN_VALUE;
                                    break;
                            }
                            switch (i7) {
                                case 1:
                                case 2:
                                case 3:
                                    i4 = 2;
                                    break;
                                case 4:
                                case 5:
                                case 6:
                                    i4 = 1;
                                    break;
                                case 7:
                                case 8:
                                case 9:
                                    i4 = 0;
                                    break;
                                default:
                                    i4 = Integer.MIN_VALUE;
                                    break;
                            }
                            if (pointF == null || f3 == -3.4028235E38f || f2 == -3.4028235E38f) {
                                m2090l = m2090l(i3);
                                m2090l2 = m2090l(i4);
                            } else {
                                float f4 = pointF.x / f2;
                                m2090l2 = pointF.y / f3;
                                m2090l = f4;
                            }
                            switch (i7) {
                                case 1:
                                case 4:
                                case 7:
                                    alignment2 = Layout.Alignment.ALIGN_NORMAL;
                                    alignment = alignment2;
                                    break;
                                case 2:
                                case 5:
                                case 8:
                                    alignment2 = Layout.Alignment.ALIGN_CENTER;
                                    alignment = alignment2;
                                    break;
                                case 3:
                                case 6:
                                case 9:
                                    alignment2 = Layout.Alignment.ALIGN_OPPOSITE;
                                    alignment = alignment2;
                                    break;
                                default:
                                    alignment = null;
                                    break;
                            }
                            C2207b c2207b = new C2207b(replaceAll, alignment, m2090l2, 0, i4, m2090l, i3, -3.4028235E38f);
                            int m2089k = m2089k(m2091n2, arrayList2, arrayList);
                            for (int m2089k2 = m2089k(m2091n, arrayList2, arrayList); m2089k2 < m2089k; m2089k2++) {
                                ((List) arrayList.get(m2089k2)).add(c2207b);
                            }
                        }
                    }
                }
            }
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:45:0x0123 A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:49:0x0078 A[SYNTHETIC] */
    /* renamed from: m */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void m2092m(p005b.p199l.p200a.p201a.p250p1.C2360t r14) {
        /*
            Method dump skipped, instructions count: 321
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.p236l1.p240p.C2228a.m2092m(b.l.a.a.p1.t):void");
    }
}
