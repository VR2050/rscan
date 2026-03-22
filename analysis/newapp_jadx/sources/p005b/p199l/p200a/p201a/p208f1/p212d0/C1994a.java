package p005b.p199l.p200a.p201a.p208f1.p212d0;

import androidx.work.WorkRequest;
import p005b.p199l.p200a.p201a.p208f1.C2003e;
import p005b.p199l.p200a.p201a.p208f1.C2051r;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2050q;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.l.a.a.f1.d0.a */
/* loaded from: classes.dex */
public final class C1994a implements InterfaceC1999f {

    /* renamed from: a */
    public final C1998e f3726a = new C1998e();

    /* renamed from: b */
    public final long f3727b;

    /* renamed from: c */
    public final long f3728c;

    /* renamed from: d */
    public final AbstractC2001h f3729d;

    /* renamed from: e */
    public int f3730e;

    /* renamed from: f */
    public long f3731f;

    /* renamed from: g */
    public long f3732g;

    /* renamed from: h */
    public long f3733h;

    /* renamed from: i */
    public long f3734i;

    /* renamed from: j */
    public long f3735j;

    /* renamed from: k */
    public long f3736k;

    /* renamed from: l */
    public long f3737l;

    /* renamed from: b.l.a.a.f1.d0.a$b */
    public final class b implements InterfaceC2050q {
        public b(a aVar) {
        }

        @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2050q
        /* renamed from: c */
        public boolean mo1462c() {
            return true;
        }

        @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2050q
        /* renamed from: g */
        public InterfaceC2050q.a mo1463g(long j2) {
            C1994a c1994a = C1994a.this;
            long j3 = (c1994a.f3729d.f3770i * j2) / 1000000;
            long j4 = c1994a.f3727b;
            long j5 = c1994a.f3728c;
            return new InterfaceC2050q.a(new C2051r(j2, C2344d0.m2330h(((((j5 - j4) * j3) / c1994a.f3731f) + j4) - WorkRequest.DEFAULT_BACKOFF_DELAY_MILLIS, j4, j5 - 1)));
        }

        @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2050q
        /* renamed from: i */
        public long mo1464i() {
            return (C1994a.this.f3731f * 1000000) / r0.f3729d.f3770i;
        }
    }

    public C1994a(AbstractC2001h abstractC2001h, long j2, long j3, long j4, long j5, boolean z) {
        C4195m.m4765F(j2 >= 0 && j3 > j2);
        this.f3729d = abstractC2001h;
        this.f3727b = j2;
        this.f3728c = j3;
        if (j4 != j3 - j2 && !z) {
            this.f3730e = 0;
        } else {
            this.f3731f = j5;
            this.f3730e = 4;
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:24:0x00ac A[RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:25:0x00ad  */
    @Override // p005b.p199l.p200a.p201a.p208f1.p212d0.InterfaceC1999f
    /* renamed from: a */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public long mo1546a(p005b.p199l.p200a.p201a.p208f1.C2003e r24) {
        /*
            Method dump skipped, instructions count: 305
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.p208f1.p212d0.C1994a.mo1546a(b.l.a.a.f1.e):long");
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.p212d0.InterfaceC1999f
    /* renamed from: b */
    public InterfaceC2050q mo1547b() {
        if (this.f3731f != 0) {
            return new b(null);
        }
        return null;
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.p212d0.InterfaceC1999f
    /* renamed from: c */
    public void mo1548c(long j2) {
        this.f3733h = C2344d0.m2330h(j2, 0L, this.f3731f - 1);
        this.f3730e = 2;
        this.f3734i = this.f3727b;
        this.f3735j = this.f3728c;
        this.f3736k = 0L;
        this.f3737l = this.f3731f;
    }

    /* renamed from: d */
    public final boolean m1549d(C2003e c2003e, long j2) {
        int i2;
        long min = Math.min(j2 + 3, this.f3728c);
        int i3 = 2048;
        byte[] bArr = new byte[2048];
        while (true) {
            long j3 = c2003e.f3789d;
            int i4 = 0;
            if (i3 + j3 > min && (i3 = (int) (min - j3)) < 4) {
                return false;
            }
            c2003e.m1565e(bArr, 0, i3, false);
            while (true) {
                i2 = i3 - 3;
                if (i4 < i2) {
                    if (bArr[i4] == 79 && bArr[i4 + 1] == 103 && bArr[i4 + 2] == 103 && bArr[i4 + 3] == 83) {
                        c2003e.m1569i(i4);
                        return true;
                    }
                    i4++;
                }
            }
            c2003e.m1569i(i2);
        }
    }
}
