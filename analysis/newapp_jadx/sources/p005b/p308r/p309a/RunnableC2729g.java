package p005b.p308r.p309a;

/* renamed from: b.r.a.g */
/* loaded from: classes2.dex */
public class RunnableC2729g implements Runnable {

    /* renamed from: c */
    public final /* synthetic */ C2730h f7429c;

    public RunnableC2729g(C2730h c2730h) {
        this.f7429c = c2730h;
    }

    @Override // java.lang.Runnable
    public void run() {
        C2730h c2730h = this.f7429c;
        float f2 = c2730h.f7430c + 30.0f;
        c2730h.f7430c = f2;
        if (f2 >= 360.0f) {
            f2 -= 360.0f;
        }
        c2730h.f7430c = f2;
        c2730h.invalidate();
        C2730h c2730h2 = this.f7429c;
        if (c2730h2.f7432f) {
            c2730h2.postDelayed(this, c2730h2.f7431e);
        }
    }
}
