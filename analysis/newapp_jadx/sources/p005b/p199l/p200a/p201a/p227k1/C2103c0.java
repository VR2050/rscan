package p005b.p199l.p200a.p201a.p227k1;

import androidx.annotation.Nullable;
import java.nio.ByteBuffer;
import p005b.p199l.p200a.p201a.p248o1.C2286d;
import p005b.p199l.p200a.p201a.p248o1.C2325q;
import p005b.p199l.p200a.p201a.p248o1.InterfaceC2288e;
import p005b.p199l.p200a.p201a.p250p1.C2360t;

/* renamed from: b.l.a.a.k1.c0 */
/* loaded from: classes.dex */
public class C2103c0 {

    /* renamed from: a */
    public final InterfaceC2288e f4522a;

    /* renamed from: b */
    public final int f4523b;

    /* renamed from: c */
    public final C2360t f4524c;

    /* renamed from: d */
    public a f4525d;

    /* renamed from: e */
    public a f4526e;

    /* renamed from: f */
    public a f4527f;

    /* renamed from: g */
    public long f4528g;

    /* renamed from: b.l.a.a.k1.c0$a */
    public static final class a {

        /* renamed from: a */
        public final long f4529a;

        /* renamed from: b */
        public final long f4530b;

        /* renamed from: c */
        public boolean f4531c;

        /* renamed from: d */
        @Nullable
        public C2286d f4532d;

        /* renamed from: e */
        @Nullable
        public a f4533e;

        public a(long j2, int i2) {
            this.f4529a = j2;
            this.f4530b = j2 + i2;
        }

        /* renamed from: a */
        public int m1802a(long j2) {
            return ((int) (j2 - this.f4529a)) + this.f4532d.f5795b;
        }
    }

    public C2103c0(InterfaceC2288e interfaceC2288e) {
        this.f4522a = interfaceC2288e;
        int i2 = ((C2325q) interfaceC2288e).f5943b;
        this.f4523b = i2;
        this.f4524c = new C2360t(32);
        a aVar = new a(0L, i2);
        this.f4525d = aVar;
        this.f4526e = aVar;
        this.f4527f = aVar;
    }

    /* renamed from: a */
    public final void m1796a(a aVar) {
        if (aVar.f4531c) {
            a aVar2 = this.f4527f;
            int i2 = (((int) (aVar2.f4529a - aVar.f4529a)) / this.f4523b) + (aVar2.f4531c ? 1 : 0);
            C2286d[] c2286dArr = new C2286d[i2];
            int i3 = 0;
            while (i3 < i2) {
                c2286dArr[i3] = aVar.f4532d;
                aVar.f4532d = null;
                a aVar3 = aVar.f4533e;
                aVar.f4533e = null;
                i3++;
                aVar = aVar3;
            }
            ((C2325q) this.f4522a).m2270a(c2286dArr);
        }
    }

    /* renamed from: b */
    public void m1797b(long j2) {
        a aVar;
        if (j2 == -1) {
            return;
        }
        while (true) {
            aVar = this.f4525d;
            if (j2 < aVar.f4530b) {
                break;
            }
            InterfaceC2288e interfaceC2288e = this.f4522a;
            C2286d c2286d = aVar.f4532d;
            C2325q c2325q = (C2325q) interfaceC2288e;
            synchronized (c2325q) {
                C2286d[] c2286dArr = c2325q.f5944c;
                c2286dArr[0] = c2286d;
                c2325q.m2270a(c2286dArr);
            }
            a aVar2 = this.f4525d;
            aVar2.f4532d = null;
            a aVar3 = aVar2.f4533e;
            aVar2.f4533e = null;
            this.f4525d = aVar3;
        }
        if (this.f4526e.f4529a < aVar.f4529a) {
            this.f4526e = aVar;
        }
    }

    /* renamed from: c */
    public final void m1798c(int i2) {
        long j2 = this.f4528g + i2;
        this.f4528g = j2;
        a aVar = this.f4527f;
        if (j2 == aVar.f4530b) {
            this.f4527f = aVar.f4533e;
        }
    }

    /* renamed from: d */
    public final int m1799d(int i2) {
        C2286d c2286d;
        a aVar = this.f4527f;
        if (!aVar.f4531c) {
            C2325q c2325q = (C2325q) this.f4522a;
            synchronized (c2325q) {
                c2325q.f5946e++;
                int i3 = c2325q.f5947f;
                if (i3 > 0) {
                    C2286d[] c2286dArr = c2325q.f5948g;
                    int i4 = i3 - 1;
                    c2325q.f5947f = i4;
                    c2286d = c2286dArr[i4];
                    c2286dArr[i4] = null;
                } else {
                    c2286d = new C2286d(new byte[c2325q.f5943b], 0);
                }
            }
            a aVar2 = new a(this.f4527f.f4530b, this.f4523b);
            aVar.f4532d = c2286d;
            aVar.f4533e = aVar2;
            aVar.f4531c = true;
        }
        return Math.min(i2, (int) (this.f4527f.f4530b - this.f4528g));
    }

    /* renamed from: e */
    public final void m1800e(long j2, ByteBuffer byteBuffer, int i2) {
        while (true) {
            a aVar = this.f4526e;
            if (j2 < aVar.f4530b) {
                break;
            } else {
                this.f4526e = aVar.f4533e;
            }
        }
        while (i2 > 0) {
            int min = Math.min(i2, (int) (this.f4526e.f4530b - j2));
            a aVar2 = this.f4526e;
            byteBuffer.put(aVar2.f4532d.f5794a, aVar2.m1802a(j2), min);
            i2 -= min;
            j2 += min;
            a aVar3 = this.f4526e;
            if (j2 == aVar3.f4530b) {
                this.f4526e = aVar3.f4533e;
            }
        }
    }

    /* renamed from: f */
    public final void m1801f(long j2, byte[] bArr, int i2) {
        while (true) {
            a aVar = this.f4526e;
            if (j2 < aVar.f4530b) {
                break;
            } else {
                this.f4526e = aVar.f4533e;
            }
        }
        int i3 = i2;
        while (i3 > 0) {
            int min = Math.min(i3, (int) (this.f4526e.f4530b - j2));
            a aVar2 = this.f4526e;
            System.arraycopy(aVar2.f4532d.f5794a, aVar2.m1802a(j2), bArr, i2 - i3, min);
            i3 -= min;
            j2 += min;
            a aVar3 = this.f4526e;
            if (j2 == aVar3.f4530b) {
                this.f4526e = aVar3.f4533e;
            }
        }
    }
}
