package p005b.p199l.p200a.p201a;

import androidx.annotation.Nullable;
import p005b.p199l.p200a.p201a.AbstractC2404x0;
import p005b.p199l.p200a.p201a.InterfaceC2368q0;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;

/* renamed from: b.l.a.a.t */
/* loaded from: classes.dex */
public abstract class AbstractC2395t implements InterfaceC2368q0 {

    /* renamed from: a */
    public final AbstractC2404x0.c f6311a = new AbstractC2404x0.c();

    /* renamed from: b.l.a.a.t$a */
    public static final class a {

        /* renamed from: a */
        public final InterfaceC2368q0.a f6312a;

        /* renamed from: b */
        public boolean f6313b;

        public a(InterfaceC2368q0.a aVar) {
            this.f6312a = aVar;
        }

        public boolean equals(@Nullable Object obj) {
            if (this == obj) {
                return true;
            }
            if (obj == null || a.class != obj.getClass()) {
                return false;
            }
            return this.f6312a.equals(((a) obj).f6312a);
        }

        public int hashCode() {
            return this.f6312a.hashCode();
        }
    }

    /* renamed from: b.l.a.a.t$b */
    public interface b {
        /* renamed from: a */
        void mo1338a(InterfaceC2368q0.a aVar);
    }

    /* renamed from: F */
    public final int m2651F() {
        long mo1371t = mo1371t();
        long duration = getDuration();
        if (mo1371t == -9223372036854775807L || duration == -9223372036854775807L) {
            return 0;
        }
        if (duration == 0) {
            return 100;
        }
        return C2344d0.m2329g((int) ((mo1371t * 100) / duration), 0, 100);
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0
    public final boolean hasNext() {
        return mo2612v() != -1;
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0
    public final boolean hasPrevious() {
        return mo2611s() != -1;
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0
    public final boolean isPlaying() {
        return mo1354a() == 3 && mo1361h() && mo1373w() == 0;
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0
    /* renamed from: k */
    public final boolean mo2610k() {
        AbstractC2404x0 mo1375y = mo1375y();
        return !mo1375y.m2691q() && mo1375y.m2690n(mo1367o(), this.f6311a).f6376e;
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0
    /* renamed from: s */
    public final int mo2611s() {
        AbstractC2404x0 mo1375y = mo1375y();
        if (mo1375y.m2691q()) {
            return -1;
        }
        int mo1367o = mo1367o();
        int mo1358e = mo1358e();
        if (mo1358e == 1) {
            mo1358e = 0;
        }
        return mo1375y.mo1930l(mo1367o, mo1358e, mo1340A());
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0
    /* renamed from: v */
    public final int mo2612v() {
        AbstractC2404x0 mo1375y = mo1375y();
        if (mo1375y.m2691q()) {
            return -1;
        }
        int mo1367o = mo1367o();
        int mo1358e = mo1358e();
        if (mo1358e == 1) {
            mo1358e = 0;
        }
        return mo1375y.mo1928e(mo1367o, mo1358e, mo1340A());
    }
}
