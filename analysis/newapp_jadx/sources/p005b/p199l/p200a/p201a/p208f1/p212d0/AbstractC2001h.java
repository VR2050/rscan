package p005b.p199l.p200a.p201a.p208f1.p212d0;

import com.google.android.exoplayer2.Format;
import p005b.p199l.p200a.p201a.p208f1.C2003e;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2042i;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2050q;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2052s;
import p005b.p199l.p200a.p201a.p250p1.C2360t;

/* renamed from: b.l.a.a.f1.d0.h */
/* loaded from: classes.dex */
public abstract class AbstractC2001h {

    /* renamed from: a */
    public final C1997d f3762a = new C1997d();

    /* renamed from: b */
    public InterfaceC2052s f3763b;

    /* renamed from: c */
    public InterfaceC2042i f3764c;

    /* renamed from: d */
    public InterfaceC1999f f3765d;

    /* renamed from: e */
    public long f3766e;

    /* renamed from: f */
    public long f3767f;

    /* renamed from: g */
    public long f3768g;

    /* renamed from: h */
    public int f3769h;

    /* renamed from: i */
    public int f3770i;

    /* renamed from: j */
    public b f3771j;

    /* renamed from: k */
    public long f3772k;

    /* renamed from: l */
    public boolean f3773l;

    /* renamed from: m */
    public boolean f3774m;

    /* renamed from: b.l.a.a.f1.d0.h$b */
    public static class b {

        /* renamed from: a */
        public Format f3775a;

        /* renamed from: b */
        public InterfaceC1999f f3776b;
    }

    /* renamed from: b.l.a.a.f1.d0.h$c */
    public static final class c implements InterfaceC1999f {
        public c(a aVar) {
        }

        @Override // p005b.p199l.p200a.p201a.p208f1.p212d0.InterfaceC1999f
        /* renamed from: a */
        public long mo1546a(C2003e c2003e) {
            return -1L;
        }

        @Override // p005b.p199l.p200a.p201a.p208f1.p212d0.InterfaceC1999f
        /* renamed from: b */
        public InterfaceC2050q mo1547b() {
            return new InterfaceC2050q.b(-9223372036854775807L, 0L);
        }

        @Override // p005b.p199l.p200a.p201a.p208f1.p212d0.InterfaceC1999f
        /* renamed from: c */
        public void mo1548c(long j2) {
        }
    }

    /* renamed from: a */
    public long m1559a(long j2) {
        return (this.f3770i * j2) / 1000000;
    }

    /* renamed from: b */
    public void mo1560b(long j2) {
        this.f3768g = j2;
    }

    /* renamed from: c */
    public abstract long mo1550c(C2360t c2360t);

    /* renamed from: d */
    public abstract boolean mo1551d(C2360t c2360t, long j2, b bVar);

    /* renamed from: e */
    public void mo1552e(boolean z) {
        if (z) {
            this.f3771j = new b();
            this.f3767f = 0L;
            this.f3769h = 0;
        } else {
            this.f3769h = 1;
        }
        this.f3766e = -1L;
        this.f3768g = 0L;
    }
}
