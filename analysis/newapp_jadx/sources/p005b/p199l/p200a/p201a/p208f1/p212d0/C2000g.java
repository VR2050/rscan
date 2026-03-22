package p005b.p199l.p200a.p201a.p208f1.p212d0;

import com.google.android.exoplayer2.Format;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import p005b.p199l.p200a.p201a.p208f1.p212d0.AbstractC2001h;
import p005b.p199l.p200a.p201a.p250p1.C2360t;

/* renamed from: b.l.a.a.f1.d0.g */
/* loaded from: classes.dex */
public final class C2000g extends AbstractC2001h {

    /* renamed from: n */
    public static final byte[] f3760n = {79, 112, 117, 115, 72, 101, 97, 100};

    /* renamed from: o */
    public boolean f3761o;

    @Override // p005b.p199l.p200a.p201a.p208f1.p212d0.AbstractC2001h
    /* renamed from: c */
    public long mo1550c(C2360t c2360t) {
        byte[] bArr = c2360t.f6133a;
        int i2 = bArr[0] & 255;
        int i3 = i2 & 3;
        int i4 = 2;
        if (i3 == 0) {
            i4 = 1;
        } else if (i3 != 1 && i3 != 2) {
            i4 = bArr[1] & 63;
        }
        int i5 = i2 >> 3;
        return m1559a(i4 * (i5 >= 16 ? 2500 << r1 : i5 >= 12 ? 10000 << (r1 & 1) : (i5 & 3) == 3 ? 60000 : 10000 << r1));
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.p212d0.AbstractC2001h
    /* renamed from: d */
    public boolean mo1551d(C2360t c2360t, long j2, AbstractC2001h.b bVar) {
        if (this.f3761o) {
            boolean z = c2360t.m2573e() == 1332770163;
            c2360t.m2567C(0);
            return z;
        }
        byte[] copyOf = Arrays.copyOf(c2360t.f6133a, c2360t.f6135c);
        int i2 = copyOf[9] & 255;
        int i3 = ((copyOf[11] & 255) << 8) | (copyOf[10] & 255);
        ArrayList arrayList = new ArrayList(3);
        arrayList.add(copyOf);
        m1558f(arrayList, i3);
        m1558f(arrayList, 3840);
        bVar.f3775a = Format.m4024A(null, "audio/opus", null, -1, -1, i2, 48000, arrayList, null, 0, null);
        this.f3761o = true;
        return true;
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.p212d0.AbstractC2001h
    /* renamed from: e */
    public void mo1552e(boolean z) {
        super.mo1552e(z);
        if (z) {
            this.f3761o = false;
        }
    }

    /* renamed from: f */
    public final void m1558f(List<byte[]> list, int i2) {
        list.add(ByteBuffer.allocate(8).order(ByteOrder.nativeOrder()).putLong((i2 * 1000000000) / 48000).array());
    }
}
