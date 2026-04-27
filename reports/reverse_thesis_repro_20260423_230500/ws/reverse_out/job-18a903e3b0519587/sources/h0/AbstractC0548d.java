package h0;

import X.n;

/* JADX INFO: renamed from: h0.d, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public abstract class AbstractC0548d {

    /* JADX INFO: renamed from: h0.d$a */
    class a implements n {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        final /* synthetic */ Throwable f9249a;

        a(Throwable th) {
            this.f9249a = th;
        }

        @Override // X.n
        /* JADX INFO: renamed from: a, reason: merged with bridge method [inline-methods] */
        public InterfaceC0547c get() {
            return AbstractC0548d.b(this.f9249a);
        }
    }

    public static n a(Throwable th) {
        return new a(th);
    }

    public static InterfaceC0547c b(Throwable th) {
        C0553i c0553iY = C0553i.y();
        c0553iY.q(th);
        return c0553iY;
    }
}
