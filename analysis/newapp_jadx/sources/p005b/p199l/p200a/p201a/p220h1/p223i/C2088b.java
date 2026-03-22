package p005b.p199l.p200a.p201a.p220h1.p223i;

import androidx.annotation.Nullable;
import com.google.android.exoplayer2.metadata.Metadata;
import com.google.android.exoplayer2.metadata.id3.ApicFrame;
import com.google.android.exoplayer2.metadata.id3.BinaryFrame;
import com.google.android.exoplayer2.metadata.id3.ChapterFrame;
import com.google.android.exoplayer2.metadata.id3.ChapterTocFrame;
import com.google.android.exoplayer2.metadata.id3.CommentFrame;
import com.google.android.exoplayer2.metadata.id3.GeobFrame;
import com.google.android.exoplayer2.metadata.id3.Id3Frame;
import com.google.android.exoplayer2.metadata.id3.MlltFrame;
import com.google.android.exoplayer2.metadata.id3.PrivFrame;
import com.google.android.exoplayer2.metadata.id3.TextInformationFrame;
import com.google.android.exoplayer2.metadata.id3.UrlLinkFrame;
import com.luck.picture.lib.compress.Checker;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Locale;
import java.util.Objects;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p220h1.C2081d;
import p005b.p199l.p200a.p201a.p220h1.InterfaceC2079b;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;
import p005b.p199l.p200a.p201a.p250p1.C2359s;
import p005b.p199l.p200a.p201a.p250p1.C2360t;

/* renamed from: b.l.a.a.h1.i.b */
/* loaded from: classes.dex */
public final class C2088b implements InterfaceC2079b {

    /* renamed from: a */
    public static final /* synthetic */ int f4389a = 0;

    /* renamed from: b */
    @Nullable
    public final a f4390b;

    /* renamed from: b.l.a.a.h1.i.b$a */
    public interface a {
        /* renamed from: a */
        boolean mo1501a(int i2, int i3, int i4, int i5, int i6);
    }

    /* renamed from: b.l.a.a.h1.i.b$b */
    public static final class b {

        /* renamed from: a */
        public final int f4391a;

        /* renamed from: b */
        public final boolean f4392b;

        /* renamed from: c */
        public final int f4393c;

        public b(int i2, boolean z, int i3) {
            this.f4391a = i2;
            this.f4392b = z;
            this.f4393c = i3;
        }
    }

    public C2088b() {
        this.f4390b = null;
    }

    /* renamed from: b */
    public static byte[] m1712b(byte[] bArr, int i2, int i3) {
        return i3 <= i2 ? C2344d0.f6040f : Arrays.copyOfRange(bArr, i2, i3);
    }

    /* renamed from: d */
    public static ApicFrame m1713d(C2360t c2360t, int i2, int i3) {
        int i4;
        String str;
        int m2585q = c2360t.m2585q();
        String m1728s = m1728s(m2585q);
        int i5 = i2 - 1;
        byte[] bArr = new byte[i5];
        System.arraycopy(c2360t.f6133a, c2360t.f6134b, bArr, 0, i5);
        c2360t.f6134b += i5;
        if (i3 == 2) {
            StringBuilder m586H = C1499a.m586H("image/");
            m586H.append(C2344d0.m2320L(new String(bArr, 0, 3, "ISO-8859-1")));
            str = m586H.toString();
            if (Checker.MIME_TYPE_JPG.equals(str)) {
                str = "image/jpeg";
            }
            i4 = 2;
        } else {
            int m1731v = m1731v(bArr, 0);
            String m2320L = C2344d0.m2320L(new String(bArr, 0, m1731v, "ISO-8859-1"));
            if (m2320L.indexOf(47) == -1) {
                i4 = m1731v;
                str = C1499a.m637w("image/", m2320L);
            } else {
                i4 = m1731v;
                str = m2320L;
            }
        }
        int i6 = bArr[i4 + 1] & 255;
        int i7 = i4 + 2;
        int m1730u = m1730u(bArr, i7, m2585q);
        return new ApicFrame(str, new String(bArr, i7, m1730u - i7, m1728s), i6, m1712b(bArr, m1727r(m2585q) + m1730u, i5));
    }

    /* renamed from: e */
    public static BinaryFrame m1714e(C2360t c2360t, int i2, String str) {
        byte[] bArr = new byte[i2];
        System.arraycopy(c2360t.f6133a, c2360t.f6134b, bArr, 0, i2);
        c2360t.f6134b += i2;
        return new BinaryFrame(str, bArr);
    }

    /* renamed from: f */
    public static ChapterFrame m1715f(C2360t c2360t, int i2, int i3, boolean z, int i4, @Nullable a aVar) {
        int i5 = c2360t.f6134b;
        int m1731v = m1731v(c2360t.f6133a, i5);
        String str = new String(c2360t.f6133a, i5, m1731v - i5, "ISO-8859-1");
        c2360t.m2567C(m1731v + 1);
        int m2573e = c2360t.m2573e();
        int m2573e2 = c2360t.m2573e();
        long m2586r = c2360t.m2586r();
        long j2 = m2586r == 4294967295L ? -1L : m2586r;
        long m2586r2 = c2360t.m2586r();
        long j3 = m2586r2 == 4294967295L ? -1L : m2586r2;
        ArrayList arrayList = new ArrayList();
        int i6 = i5 + i2;
        while (c2360t.f6134b < i6) {
            Id3Frame m1718i = m1718i(i3, c2360t, z, i4, aVar);
            if (m1718i != null) {
                arrayList.add(m1718i);
            }
        }
        Id3Frame[] id3FrameArr = new Id3Frame[arrayList.size()];
        arrayList.toArray(id3FrameArr);
        return new ChapterFrame(str, m2573e, m2573e2, j2, j3, id3FrameArr);
    }

    /* renamed from: g */
    public static ChapterTocFrame m1716g(C2360t c2360t, int i2, int i3, boolean z, int i4, @Nullable a aVar) {
        int i5 = c2360t.f6134b;
        int m1731v = m1731v(c2360t.f6133a, i5);
        String str = new String(c2360t.f6133a, i5, m1731v - i5, "ISO-8859-1");
        c2360t.m2567C(m1731v + 1);
        int m2585q = c2360t.m2585q();
        boolean z2 = (m2585q & 2) != 0;
        boolean z3 = (m2585q & 1) != 0;
        int m2585q2 = c2360t.m2585q();
        String[] strArr = new String[m2585q2];
        for (int i6 = 0; i6 < m2585q2; i6++) {
            int i7 = c2360t.f6134b;
            int m1731v2 = m1731v(c2360t.f6133a, i7);
            strArr[i6] = new String(c2360t.f6133a, i7, m1731v2 - i7, "ISO-8859-1");
            c2360t.m2567C(m1731v2 + 1);
        }
        ArrayList arrayList = new ArrayList();
        int i8 = i5 + i2;
        while (c2360t.f6134b < i8) {
            Id3Frame m1718i = m1718i(i3, c2360t, z, i4, aVar);
            if (m1718i != null) {
                arrayList.add(m1718i);
            }
        }
        Id3Frame[] id3FrameArr = new Id3Frame[arrayList.size()];
        arrayList.toArray(id3FrameArr);
        return new ChapterTocFrame(str, z2, z3, strArr, id3FrameArr);
    }

    @Nullable
    /* renamed from: h */
    public static CommentFrame m1717h(C2360t c2360t, int i2) {
        if (i2 < 4) {
            return null;
        }
        int m2585q = c2360t.m2585q();
        String m1728s = m1728s(m2585q);
        byte[] bArr = new byte[3];
        System.arraycopy(c2360t.f6133a, c2360t.f6134b, bArr, 0, 3);
        c2360t.f6134b += 3;
        String str = new String(bArr, 0, 3);
        int i3 = i2 - 4;
        byte[] bArr2 = new byte[i3];
        System.arraycopy(c2360t.f6133a, c2360t.f6134b, bArr2, 0, i3);
        c2360t.f6134b += i3;
        int m1730u = m1730u(bArr2, 0, m2585q);
        String str2 = new String(bArr2, 0, m1730u, m1728s);
        int m1727r = m1727r(m2585q) + m1730u;
        return new CommentFrame(str, str2, m1722m(bArr2, m1727r, m1730u(bArr2, m1727r, m2585q), m1728s));
    }

    /* JADX WARN: Code restructure failed: missing block: B:127:0x017f, code lost:
    
        if (r13 == 67) goto L133;
     */
    @androidx.annotation.Nullable
    /* renamed from: i */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static com.google.android.exoplayer2.metadata.id3.Id3Frame m1718i(int r19, p005b.p199l.p200a.p201a.p250p1.C2360t r20, boolean r21, int r22, @androidx.annotation.Nullable p005b.p199l.p200a.p201a.p220h1.p223i.C2088b.a r23) {
        /*
            Method dump skipped, instructions count: 499
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.p220h1.p223i.C2088b.m1718i(int, b.l.a.a.p1.t, boolean, int, b.l.a.a.h1.i.b$a):com.google.android.exoplayer2.metadata.id3.Id3Frame");
    }

    /* renamed from: j */
    public static GeobFrame m1719j(C2360t c2360t, int i2) {
        int m2585q = c2360t.m2585q();
        String m1728s = m1728s(m2585q);
        int i3 = i2 - 1;
        byte[] bArr = new byte[i3];
        System.arraycopy(c2360t.f6133a, c2360t.f6134b, bArr, 0, i3);
        c2360t.f6134b += i3;
        int m1731v = m1731v(bArr, 0);
        String str = new String(bArr, 0, m1731v, "ISO-8859-1");
        int i4 = m1731v + 1;
        int m1730u = m1730u(bArr, i4, m2585q);
        String m1722m = m1722m(bArr, i4, m1730u, m1728s);
        int m1727r = m1727r(m2585q) + m1730u;
        int m1730u2 = m1730u(bArr, m1727r, m2585q);
        return new GeobFrame(str, m1722m, m1722m(bArr, m1727r, m1730u2, m1728s), m1712b(bArr, m1727r(m2585q) + m1730u2, i3));
    }

    /* renamed from: k */
    public static MlltFrame m1720k(C2360t c2360t, int i2) {
        int m2590v = c2360t.m2590v();
        int m2587s = c2360t.m2587s();
        int m2587s2 = c2360t.m2587s();
        int m2585q = c2360t.m2585q();
        int m2585q2 = c2360t.m2585q();
        C2359s c2359s = new C2359s();
        c2359s.m2561i(c2360t.f6133a, c2360t.f6135c);
        c2359s.m2562j(c2360t.f6134b * 8);
        int i3 = ((i2 - 10) * 8) / (m2585q + m2585q2);
        int[] iArr = new int[i3];
        int[] iArr2 = new int[i3];
        for (int i4 = 0; i4 < i3; i4++) {
            int m2558f = c2359s.m2558f(m2585q);
            int m2558f2 = c2359s.m2558f(m2585q2);
            iArr[i4] = m2558f;
            iArr2[i4] = m2558f2;
        }
        return new MlltFrame(m2590v, m2587s, m2587s2, iArr, iArr2);
    }

    /* renamed from: l */
    public static PrivFrame m1721l(C2360t c2360t, int i2) {
        byte[] bArr = new byte[i2];
        System.arraycopy(c2360t.f6133a, c2360t.f6134b, bArr, 0, i2);
        c2360t.f6134b += i2;
        int m1731v = m1731v(bArr, 0);
        return new PrivFrame(new String(bArr, 0, m1731v, "ISO-8859-1"), m1712b(bArr, m1731v + 1, i2));
    }

    /* renamed from: m */
    public static String m1722m(byte[] bArr, int i2, int i3, String str) {
        return (i3 <= i2 || i3 > bArr.length) ? "" : new String(bArr, i2, i3 - i2, str);
    }

    @Nullable
    /* renamed from: n */
    public static TextInformationFrame m1723n(C2360t c2360t, int i2, String str) {
        if (i2 < 1) {
            return null;
        }
        int m2585q = c2360t.m2585q();
        String m1728s = m1728s(m2585q);
        int i3 = i2 - 1;
        byte[] bArr = new byte[i3];
        System.arraycopy(c2360t.f6133a, c2360t.f6134b, bArr, 0, i3);
        c2360t.f6134b += i3;
        return new TextInformationFrame(str, null, new String(bArr, 0, m1730u(bArr, 0, m2585q), m1728s));
    }

    @Nullable
    /* renamed from: o */
    public static TextInformationFrame m1724o(C2360t c2360t, int i2) {
        if (i2 < 1) {
            return null;
        }
        int m2585q = c2360t.m2585q();
        String m1728s = m1728s(m2585q);
        int i3 = i2 - 1;
        byte[] bArr = new byte[i3];
        System.arraycopy(c2360t.f6133a, c2360t.f6134b, bArr, 0, i3);
        c2360t.f6134b += i3;
        int m1730u = m1730u(bArr, 0, m2585q);
        String str = new String(bArr, 0, m1730u, m1728s);
        int m1727r = m1727r(m2585q) + m1730u;
        return new TextInformationFrame("TXXX", str, m1722m(bArr, m1727r, m1730u(bArr, m1727r, m2585q), m1728s));
    }

    /* renamed from: p */
    public static UrlLinkFrame m1725p(C2360t c2360t, int i2, String str) {
        byte[] bArr = new byte[i2];
        System.arraycopy(c2360t.f6133a, c2360t.f6134b, bArr, 0, i2);
        c2360t.f6134b += i2;
        return new UrlLinkFrame(str, null, new String(bArr, 0, m1731v(bArr, 0), "ISO-8859-1"));
    }

    @Nullable
    /* renamed from: q */
    public static UrlLinkFrame m1726q(C2360t c2360t, int i2) {
        if (i2 < 1) {
            return null;
        }
        int m2585q = c2360t.m2585q();
        String m1728s = m1728s(m2585q);
        int i3 = i2 - 1;
        byte[] bArr = new byte[i3];
        System.arraycopy(c2360t.f6133a, c2360t.f6134b, bArr, 0, i3);
        c2360t.f6134b += i3;
        int m1730u = m1730u(bArr, 0, m2585q);
        String str = new String(bArr, 0, m1730u, m1728s);
        int m1727r = m1727r(m2585q) + m1730u;
        return new UrlLinkFrame("WXXX", str, m1722m(bArr, m1727r, m1731v(bArr, m1727r), "ISO-8859-1"));
    }

    /* renamed from: r */
    public static int m1727r(int i2) {
        return (i2 == 0 || i2 == 3) ? 1 : 2;
    }

    /* renamed from: s */
    public static String m1728s(int i2) {
        return i2 != 1 ? i2 != 2 ? i2 != 3 ? "ISO-8859-1" : "UTF-8" : "UTF-16BE" : "UTF-16";
    }

    /* renamed from: t */
    public static String m1729t(int i2, int i3, int i4, int i5, int i6) {
        return i2 == 2 ? String.format(Locale.US, "%c%c%c", Integer.valueOf(i3), Integer.valueOf(i4), Integer.valueOf(i5)) : String.format(Locale.US, "%c%c%c%c", Integer.valueOf(i3), Integer.valueOf(i4), Integer.valueOf(i5), Integer.valueOf(i6));
    }

    /* renamed from: u */
    public static int m1730u(byte[] bArr, int i2, int i3) {
        int m1731v = m1731v(bArr, i2);
        if (i3 == 0 || i3 == 3) {
            return m1731v;
        }
        while (m1731v < bArr.length - 1) {
            if (m1731v % 2 == 0 && bArr[m1731v + 1] == 0) {
                return m1731v;
            }
            m1731v = m1731v(bArr, m1731v + 1);
        }
        return bArr.length;
    }

    /* renamed from: v */
    public static int m1731v(byte[] bArr, int i2) {
        while (i2 < bArr.length) {
            if (bArr[i2] == 0) {
                return i2;
            }
            i2++;
        }
        return bArr.length;
    }

    /* renamed from: w */
    public static int m1732w(C2360t c2360t, int i2) {
        byte[] bArr = c2360t.f6133a;
        int i3 = c2360t.f6134b;
        int i4 = i3;
        while (true) {
            int i5 = i4 + 1;
            if (i5 >= i3 + i2) {
                return i2;
            }
            if ((bArr[i4] & 255) == 255 && bArr[i5] == 0) {
                System.arraycopy(bArr, i4 + 2, bArr, i5, (i2 - (i4 - i3)) - 2);
                i2--;
            }
            i4 = i5;
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:31:0x0074, code lost:
    
        if ((r10 & 1) != 0) goto L43;
     */
    /* JADX WARN: Code restructure failed: missing block: B:54:0x0082, code lost:
    
        if ((r10 & 128) != 0) goto L43;
     */
    /* renamed from: x */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static boolean m1733x(p005b.p199l.p200a.p201a.p250p1.C2360t r18, int r19, int r20, boolean r21) {
        /*
            r1 = r18
            r0 = r19
            int r2 = r1.f6134b
        L6:
            int r3 = r18.m2569a()     // Catch: java.lang.Throwable -> Lab
            r4 = 1
            r5 = r20
            if (r3 < r5) goto La7
            r3 = 3
            r6 = 0
            if (r0 < r3) goto L20
            int r7 = r18.m2573e()     // Catch: java.lang.Throwable -> Lab
            long r8 = r18.m2586r()     // Catch: java.lang.Throwable -> Lab
            int r10 = r18.m2590v()     // Catch: java.lang.Throwable -> Lab
            goto L2a
        L20:
            int r7 = r18.m2587s()     // Catch: java.lang.Throwable -> Lab
            int r8 = r18.m2587s()     // Catch: java.lang.Throwable -> Lab
            long r8 = (long) r8
            r10 = 0
        L2a:
            r11 = 0
            if (r7 != 0) goto L38
            int r7 = (r8 > r11 ? 1 : (r8 == r11 ? 0 : -1))
            if (r7 != 0) goto L38
            if (r10 != 0) goto L38
            r1.m2567C(r2)
            return r4
        L38:
            r7 = 4
            if (r0 != r7) goto L69
            if (r21 != 0) goto L69
            r13 = 8421504(0x808080, double:4.160776E-317)
            long r13 = r13 & r8
            int r15 = (r13 > r11 ? 1 : (r13 == r11 ? 0 : -1))
            if (r15 == 0) goto L49
            r1.m2567C(r2)
            return r6
        L49:
            r11 = 255(0xff, double:1.26E-321)
            long r13 = r8 & r11
            r15 = 8
            long r15 = r8 >> r15
            long r15 = r15 & r11
            r17 = 7
            long r15 = r15 << r17
            long r13 = r13 | r15
            r15 = 16
            long r15 = r8 >> r15
            long r15 = r15 & r11
            r17 = 14
            long r15 = r15 << r17
            long r13 = r13 | r15
            r15 = 24
            long r8 = r8 >> r15
            long r8 = r8 & r11
            r11 = 21
            long r8 = r8 << r11
            long r8 = r8 | r13
        L69:
            if (r0 != r7) goto L77
            r3 = r10 & 64
            if (r3 == 0) goto L71
            r3 = 1
            goto L72
        L71:
            r3 = 0
        L72:
            r7 = r10 & 1
            if (r7 == 0) goto L86
            goto L87
        L77:
            if (r0 != r3) goto L85
            r3 = r10 & 32
            if (r3 == 0) goto L7f
            r3 = 1
            goto L80
        L7f:
            r3 = 0
        L80:
            r7 = r10 & 128(0x80, float:1.8E-43)
            if (r7 == 0) goto L86
            goto L87
        L85:
            r3 = 0
        L86:
            r4 = 0
        L87:
            if (r4 == 0) goto L8b
            int r3 = r3 + 4
        L8b:
            long r3 = (long) r3
            int r7 = (r8 > r3 ? 1 : (r8 == r3 ? 0 : -1))
            if (r7 >= 0) goto L94
            r1.m2567C(r2)
            return r6
        L94:
            int r3 = r18.m2569a()     // Catch: java.lang.Throwable -> Lab
            long r3 = (long) r3
            int r7 = (r3 > r8 ? 1 : (r3 == r8 ? 0 : -1))
            if (r7 >= 0) goto La1
            r1.m2567C(r2)
            return r6
        La1:
            int r3 = (int) r8
            r1.m2568D(r3)     // Catch: java.lang.Throwable -> Lab
            goto L6
        La7:
            r1.m2567C(r2)
            return r4
        Lab:
            r0 = move-exception
            r1.m2567C(r2)
            throw r0
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.p220h1.p223i.C2088b.m1733x(b.l.a.a.p1.t, int, int, boolean):boolean");
    }

    @Override // p005b.p199l.p200a.p201a.p220h1.InterfaceC2079b
    @Nullable
    /* renamed from: a */
    public Metadata mo1705a(C2081d c2081d) {
        ByteBuffer byteBuffer = c2081d.f3306e;
        Objects.requireNonNull(byteBuffer);
        return m1734c(byteBuffer.array(), byteBuffer.limit());
    }

    /* JADX WARN: Code restructure failed: missing block: B:11:0x0049, code lost:
    
        if (((r7 & 64) != 0) != false) goto L43;
     */
    /* JADX WARN: Removed duplicated region for block: B:18:0x0094 A[RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:20:0x0095  */
    @androidx.annotation.Nullable
    /* renamed from: c */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public com.google.android.exoplayer2.metadata.Metadata m1734c(byte[] r12, int r13) {
        /*
            Method dump skipped, instructions count: 217
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.p220h1.p223i.C2088b.m1734c(byte[], int):com.google.android.exoplayer2.metadata.Metadata");
    }

    public C2088b(@Nullable a aVar) {
        this.f4390b = aVar;
    }
}
