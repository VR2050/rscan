package p005b.p199l.p200a.p201a.p208f1.p214f0;

import com.google.android.exoplayer2.Format;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import p005b.p199l.p200a.p201a.p208f1.p214f0.InterfaceC2011c0;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.l.a.a.f1.f0.g */
/* loaded from: classes.dex */
public final class C2016g implements InterfaceC2011c0.c {

    /* renamed from: a */
    public final int f3911a;

    /* renamed from: b */
    public final List<Format> f3912b;

    public C2016g(int i2, List<Format> list) {
        this.f3911a = i2;
        this.f3912b = list;
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.p214f0.InterfaceC2011c0.c
    /* renamed from: a */
    public InterfaceC2011c0 mo1583a(int i2, InterfaceC2011c0.b bVar) {
        if (i2 == 2) {
            return new C2027r(new C2020k(new C2013d0(m1592b(bVar))));
        }
        if (i2 == 3 || i2 == 4) {
            return new C2027r(new C2025p(bVar.f3856b));
        }
        if (i2 == 15) {
            if (m1593c(2)) {
                return null;
            }
            return new C2027r(new C2015f(false, bVar.f3856b));
        }
        if (i2 == 17) {
            if (m1593c(2)) {
                return null;
            }
            return new C2027r(new C2024o(bVar.f3856b));
        }
        if (i2 == 21) {
            return new C2027r(new C2023n());
        }
        if (i2 == 27) {
            if (m1593c(4)) {
                return null;
            }
            return new C2027r(new C2021l(new C2033x(m1592b(bVar)), m1593c(1), m1593c(8)));
        }
        if (i2 == 36) {
            return new C2027r(new C2022m(new C2033x(m1592b(bVar))));
        }
        if (i2 == 89) {
            return new C2027r(new C2018i(bVar.f3857c));
        }
        if (i2 != 138) {
            if (i2 == 172) {
                return new C2027r(new C2012d(bVar.f3856b));
            }
            if (i2 != 129) {
                if (i2 != 130) {
                    if (i2 == 134) {
                        if (m1593c(16)) {
                            return null;
                        }
                        return new C2032w(new C2034y());
                    }
                    if (i2 != 135) {
                        return null;
                    }
                } else if (!m1593c(64)) {
                    return null;
                }
            }
            return new C2027r(new C2008b(bVar.f3856b));
        }
        return new C2027r(new C2017h(bVar.f3856b));
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r3v2 */
    /* renamed from: b */
    public final List<Format> m1592b(InterfaceC2011c0.b bVar) {
        String str;
        int i2;
        if (m1593c(32)) {
            return this.f3912b;
        }
        byte[] bArr = bVar.f3858d;
        int length = bArr.length;
        int i3 = 0;
        ArrayList arrayList = this.f3912b;
        while (length - i3 > 0) {
            int i4 = i3 + 1;
            int i5 = bArr[i3] & 255;
            int i6 = i4 + 1;
            int i7 = (bArr[i4] & 255) + i6;
            boolean z = true;
            if (i5 == 134) {
                arrayList = new ArrayList();
                int i8 = i6 + 1;
                int i9 = bArr[i6] & 255 & 31;
                for (int i10 = 0; i10 < i9; i10++) {
                    String str2 = new String(bArr, i8, 3, Charset.forName("UTF-8"));
                    int i11 = i8 + 3;
                    int i12 = i11 + 1;
                    int i13 = bArr[i11] & 255;
                    boolean z2 = (i13 & 128) != 0;
                    if (z2) {
                        i2 = i13 & 63;
                        str = "application/cea-708";
                    } else {
                        str = "application/cea-608";
                        i2 = 1;
                    }
                    int i14 = i12 + 1;
                    byte b2 = (byte) (bArr[i12] & 255);
                    i8 = i14 + 1;
                    C4195m.m4765F(i8 >= 0 && i8 <= length);
                    arrayList.add(Format.m4032I(null, str, null, -1, 0, str2, i2, null, Long.MAX_VALUE, z2 ? Collections.singletonList(new byte[]{(byte) ((b2 & 64) != 0 ? 1 : 0)}) : null));
                }
            }
            if (i7 < 0 || i7 > length) {
                z = false;
            }
            C4195m.m4765F(z);
            i3 = i7;
            arrayList = arrayList;
        }
        return arrayList;
    }

    /* renamed from: c */
    public final boolean m1593c(int i2) {
        return (i2 & this.f3911a) != 0;
    }

    public C2016g(int i2) {
        List<Format> singletonList = Collections.singletonList(Format.m4031H(null, "application/cea-608", 0, null, null));
        this.f3911a = i2;
        this.f3912b = singletonList;
    }
}
