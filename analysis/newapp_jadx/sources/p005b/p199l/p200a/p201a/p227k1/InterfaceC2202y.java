package p005b.p199l.p200a.p201a.p227k1;

import android.os.Handler;
import androidx.annotation.Nullable;
import p005b.p199l.p200a.p201a.AbstractC2404x0;
import p005b.p199l.p200a.p201a.p248o1.InterfaceC2288e;
import p005b.p199l.p200a.p201a.p248o1.InterfaceC2291f0;

/* renamed from: b.l.a.a.k1.y */
/* loaded from: classes.dex */
public interface InterfaceC2202y {

    /* renamed from: b.l.a.a.k1.y$b */
    public interface b {
        /* renamed from: a */
        void mo1414a(InterfaceC2202y interfaceC2202y, AbstractC2404x0 abstractC2404x0);
    }

    /* renamed from: a */
    InterfaceC2201x mo1789a(a aVar, InterfaceC2288e interfaceC2288e, long j2);

    /* renamed from: b */
    void mo1992b(b bVar);

    /* renamed from: c */
    void mo1993c(Handler handler, InterfaceC2203z interfaceC2203z);

    /* renamed from: d */
    void mo1994d(InterfaceC2203z interfaceC2203z);

    /* renamed from: e */
    void mo1995e(b bVar);

    /* renamed from: f */
    void mo1790f();

    /* renamed from: g */
    void mo1791g(InterfaceC2201x interfaceC2201x);

    /* renamed from: h */
    void mo1996h(b bVar, @Nullable InterfaceC2291f0 interfaceC2291f0);

    /* renamed from: i */
    void mo1997i(b bVar);

    /* renamed from: b.l.a.a.k1.y$a */
    public static final class a {

        /* renamed from: a */
        public final Object f5247a;

        /* renamed from: b */
        public final int f5248b;

        /* renamed from: c */
        public final int f5249c;

        /* renamed from: d */
        public final long f5250d;

        /* renamed from: e */
        public final int f5251e;

        public a(Object obj) {
            this.f5247a = obj;
            this.f5248b = -1;
            this.f5249c = -1;
            this.f5250d = -1L;
            this.f5251e = -1;
        }

        /* renamed from: a */
        public boolean m2024a() {
            return this.f5248b != -1;
        }

        public boolean equals(@Nullable Object obj) {
            if (this == obj) {
                return true;
            }
            if (obj == null || a.class != obj.getClass()) {
                return false;
            }
            a aVar = (a) obj;
            return this.f5247a.equals(aVar.f5247a) && this.f5248b == aVar.f5248b && this.f5249c == aVar.f5249c && this.f5250d == aVar.f5250d && this.f5251e == aVar.f5251e;
        }

        public int hashCode() {
            return ((((((((this.f5247a.hashCode() + 527) * 31) + this.f5248b) * 31) + this.f5249c) * 31) + ((int) this.f5250d)) * 31) + this.f5251e;
        }

        public a(Object obj, int i2, int i3, long j2) {
            this.f5247a = obj;
            this.f5248b = i2;
            this.f5249c = i3;
            this.f5250d = j2;
            this.f5251e = -1;
        }

        public a(Object obj, int i2, int i3, long j2, int i4) {
            this.f5247a = obj;
            this.f5248b = i2;
            this.f5249c = i3;
            this.f5250d = j2;
            this.f5251e = i4;
        }

        public a(Object obj, long j2) {
            this.f5247a = obj;
            this.f5248b = -1;
            this.f5249c = -1;
            this.f5250d = j2;
            this.f5251e = -1;
        }

        public a(Object obj, long j2, int i2) {
            this.f5247a = obj;
            this.f5248b = -1;
            this.f5249c = -1;
            this.f5250d = j2;
            this.f5251e = i2;
        }
    }
}
