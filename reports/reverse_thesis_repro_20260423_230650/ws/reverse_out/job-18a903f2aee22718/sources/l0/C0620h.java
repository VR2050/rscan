package l0;

import G0.x;
import X.n;
import android.content.res.Resources;
import java.util.concurrent.Executor;
import o0.AbstractC0637a;

/* JADX INFO: renamed from: l0.h, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public class C0620h {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private Resources f9515a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private AbstractC0637a f9516b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private M0.a f9517c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private M0.a f9518d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private Executor f9519e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private x f9520f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private X.f f9521g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private n f9522h;

    public void a(Resources resources, AbstractC0637a abstractC0637a, M0.a aVar, M0.a aVar2, Executor executor, x xVar, X.f fVar, n nVar) {
        this.f9515a = resources;
        this.f9516b = abstractC0637a;
        this.f9517c = aVar;
        this.f9518d = aVar2;
        this.f9519e = executor;
        this.f9520f = xVar;
        this.f9521g = fVar;
        this.f9522h = nVar;
    }

    protected C0617e b(Resources resources, AbstractC0637a abstractC0637a, M0.a aVar, M0.a aVar2, Executor executor, x xVar, X.f fVar) {
        return new C0617e(resources, abstractC0637a, aVar, aVar2, executor, xVar, fVar);
    }

    public C0617e c() {
        C0617e c0617eB = b(this.f9515a, this.f9516b, this.f9517c, this.f9518d, this.f9519e, this.f9520f, this.f9521g);
        n nVar = this.f9522h;
        if (nVar != null) {
            c0617eB.B0(((Boolean) nVar.get()).booleanValue());
        }
        return c0617eB;
    }
}
