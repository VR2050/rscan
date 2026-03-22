package p005b.p199l.p200a.p201a.p208f1.p212d0;

import java.util.Arrays;
import java.util.Objects;
import kotlin.jvm.internal.ByteCompanionObject;
import p005b.p199l.p200a.p201a.p208f1.C2003e;
import p005b.p199l.p200a.p201a.p208f1.C2044k;
import p005b.p199l.p200a.p201a.p208f1.C2045l;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2050q;
import p005b.p199l.p200a.p201a.p208f1.p212d0.AbstractC2001h;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;
import p005b.p199l.p200a.p201a.p250p1.C2353m;
import p005b.p199l.p200a.p201a.p250p1.C2360t;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.l.a.a.f1.d0.b */
/* loaded from: classes.dex */
public final class C1995b extends AbstractC2001h {

    /* renamed from: n */
    public C2353m f3739n;

    /* renamed from: o */
    public a f3740o;

    /* renamed from: b.l.a.a.f1.d0.b$a */
    public class a implements InterfaceC1999f {

        /* renamed from: a */
        public long f3741a = -1;

        /* renamed from: b */
        public long f3742b = -1;

        public a() {
        }

        @Override // p005b.p199l.p200a.p201a.p208f1.p212d0.InterfaceC1999f
        /* renamed from: a */
        public long mo1546a(C2003e c2003e) {
            long j2 = this.f3742b;
            if (j2 < 0) {
                return -1L;
            }
            long j3 = -(j2 + 2);
            this.f3742b = -1L;
            return j3;
        }

        @Override // p005b.p199l.p200a.p201a.p208f1.p212d0.InterfaceC1999f
        /* renamed from: b */
        public InterfaceC2050q mo1547b() {
            C4195m.m4771I(this.f3741a != -1);
            return new C2045l(C1995b.this.f3739n, this.f3741a);
        }

        @Override // p005b.p199l.p200a.p201a.p208f1.p212d0.InterfaceC1999f
        /* renamed from: c */
        public void mo1548c(long j2) {
            Objects.requireNonNull(C1995b.this.f3739n.f6083k);
            long[] jArr = C1995b.this.f3739n.f6083k.f6085a;
            this.f3742b = jArr[C2344d0.m2326d(jArr, j2, true, true)];
        }
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.p212d0.AbstractC2001h
    /* renamed from: c */
    public long mo1550c(C2360t c2360t) {
        byte[] bArr = c2360t.f6133a;
        if (!(bArr[0] == -1)) {
            return -1L;
        }
        int i2 = (bArr[2] & 255) >> 4;
        if (i2 == 6 || i2 == 7) {
            c2360t.m2568D(4);
            c2360t.m2591w();
        }
        int m1628c = C2044k.m1628c(c2360t, i2);
        c2360t.m2567C(0);
        return m1628c;
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.p212d0.AbstractC2001h
    /* renamed from: d */
    public boolean mo1551d(C2360t c2360t, long j2, AbstractC2001h.b bVar) {
        byte[] bArr = c2360t.f6133a;
        if (this.f3739n == null) {
            this.f3739n = new C2353m(bArr, 17);
            bVar.f3775a = this.f3739n.m2371e(Arrays.copyOfRange(bArr, 9, c2360t.f6135c), null);
        } else if ((bArr[0] & ByteCompanionObject.MAX_VALUE) == 3) {
            this.f3740o = new a();
            this.f3739n = this.f3739n.m2369b(C4195m.m4766F0(c2360t));
        } else {
            if (bArr[0] == -1) {
                a aVar = this.f3740o;
                if (aVar != null) {
                    aVar.f3741a = j2;
                    bVar.f3776b = aVar;
                }
                return false;
            }
        }
        return true;
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.p212d0.AbstractC2001h
    /* renamed from: e */
    public void mo1552e(boolean z) {
        super.mo1552e(z);
        if (z) {
            this.f3739n = null;
            this.f3740o = null;
        }
    }
}
