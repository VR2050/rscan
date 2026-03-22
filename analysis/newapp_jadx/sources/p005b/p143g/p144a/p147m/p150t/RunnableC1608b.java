package p005b.p143g.p144a.p147m.p150t;

import java.util.Objects;
import p005b.p143g.p144a.p147m.p150t.C1606a;

/* renamed from: b.g.a.m.t.b */
/* loaded from: classes.dex */
public class RunnableC1608b implements Runnable {

    /* renamed from: c */
    public final /* synthetic */ C1606a f2050c;

    public RunnableC1608b(C1606a c1606a) {
        this.f2050c = c1606a;
    }

    @Override // java.lang.Runnable
    public void run() {
        C1606a c1606a = this.f2050c;
        Objects.requireNonNull(c1606a);
        while (true) {
            try {
                c1606a.m852b((C1606a.b) c1606a.f2042c.remove());
            } catch (InterruptedException unused) {
                Thread.currentThread().interrupt();
            }
        }
    }
}
