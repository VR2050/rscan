package p005b.p199l.p200a.p201a.p250p1;

import android.util.Pair;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.C2205l0;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.l.a.a.p1.g */
/* loaded from: classes.dex */
public final class C2347g {

    /* renamed from: a */
    public static final byte[] f6054a = {0, 0, 0, 1};

    /* renamed from: b */
    public static final int[] f6055b = {96000, 88200, 64000, 48000, 44100, 32000, 24000, 22050, 16000, 12000, 11025, 8000, 7350};

    /* renamed from: c */
    public static final int[] f6056c = {0, 1, 2, 3, 4, 5, 6, 8, -1, -1, -1, 7, 8, -1, 8, -1};

    /* renamed from: a */
    public static byte[] m2355a(int i2, int i3, int i4) {
        return new byte[]{(byte) (((i2 << 3) & 248) | ((i3 >> 1) & 7)), (byte) (((i3 << 7) & 128) | ((i4 << 3) & 120))};
    }

    /* renamed from: b */
    public static int m2356b(C2359s c2359s) {
        int m2558f = c2359s.m2558f(4);
        if (m2558f == 15) {
            return c2359s.m2558f(24);
        }
        C4195m.m4765F(m2558f < 13);
        return f6055b[m2558f];
    }

    /* renamed from: c */
    public static boolean m2357c(byte[] bArr, int i2) {
        if (bArr.length - i2 <= f6054a.length) {
            return false;
        }
        int i3 = 0;
        while (true) {
            byte[] bArr2 = f6054a;
            if (i3 >= bArr2.length) {
                return true;
            }
            if (bArr[i2 + i3] != bArr2[i3]) {
                return false;
            }
            i3++;
        }
    }

    /* renamed from: d */
    public static Pair<Integer, Integer> m2358d(C2359s c2359s, boolean z) {
        int m2558f = c2359s.m2558f(5);
        if (m2558f == 31) {
            m2558f = c2359s.m2558f(6) + 32;
        }
        int m2356b = m2356b(c2359s);
        int m2558f2 = c2359s.m2558f(4);
        if (m2558f == 5 || m2558f == 29) {
            m2356b = m2356b(c2359s);
            int m2558f3 = c2359s.m2558f(5);
            if (m2558f3 == 31) {
                m2558f3 = c2359s.m2558f(6) + 32;
            }
            m2558f = m2558f3;
            if (m2558f == 22) {
                m2558f2 = c2359s.m2558f(4);
            }
        }
        if (z) {
            if (m2558f != 1 && m2558f != 2 && m2558f != 3 && m2558f != 4 && m2558f != 6 && m2558f != 7 && m2558f != 17) {
                switch (m2558f) {
                    case 19:
                    case 20:
                    case 21:
                    case 22:
                    case 23:
                        break;
                    default:
                        throw new C2205l0(C1499a.m626l("Unsupported audio object type: ", m2558f));
                }
            }
            c2359s.m2564l(1);
            if (c2359s.m2557e()) {
                c2359s.m2564l(14);
            }
            boolean m2557e = c2359s.m2557e();
            if (m2558f2 == 0) {
                throw new UnsupportedOperationException();
            }
            if (m2558f == 6 || m2558f == 20) {
                c2359s.m2564l(3);
            }
            if (m2557e) {
                if (m2558f == 22) {
                    c2359s.m2564l(16);
                }
                if (m2558f == 17 || m2558f == 19 || m2558f == 20 || m2558f == 23) {
                    c2359s.m2564l(3);
                }
                c2359s.m2564l(1);
            }
            switch (m2558f) {
                case 17:
                case 19:
                case 20:
                case 21:
                case 22:
                case 23:
                    int m2558f4 = c2359s.m2558f(2);
                    if (m2558f4 == 2 || m2558f4 == 3) {
                        throw new C2205l0(C1499a.m626l("Unsupported epConfig: ", m2558f4));
                    }
            }
        }
        int i2 = f6056c[m2558f2];
        C4195m.m4765F(i2 != -1);
        return Pair.create(Integer.valueOf(m2356b), Integer.valueOf(i2));
    }

    /* renamed from: e */
    public static Pair<Integer, Integer> m2359e(byte[] bArr) {
        return m2358d(new C2359s(bArr), false);
    }
}
