package p005b.p199l.p200a.p201a.p250p1;

/* renamed from: b.l.a.a.p1.i */
/* loaded from: classes.dex */
public final class C2349i {

    /* renamed from: a */
    public boolean f6061a;

    /* renamed from: a */
    public synchronized boolean m2361a() {
        if (this.f6061a) {
            return false;
        }
        this.f6061a = true;
        notifyAll();
        return true;
    }
}
