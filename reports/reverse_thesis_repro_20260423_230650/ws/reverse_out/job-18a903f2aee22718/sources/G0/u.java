package G0;

import b0.AbstractC0311a;

/* JADX INFO: loaded from: classes.dex */
public class u implements x {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final x f819a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final z f820b;

    public u(x xVar, z zVar) {
        this.f819a = xVar;
        this.f820b = zVar;
    }

    @Override // G0.x
    public AbstractC0311a b(Object obj, AbstractC0311a abstractC0311a) {
        this.f820b.a(obj);
        return this.f819a.b(obj, abstractC0311a);
    }

    @Override // G0.x
    public void c(Object obj) {
        this.f819a.c(obj);
    }

    @Override // G0.x
    public boolean d(X.l lVar) {
        return this.f819a.d(lVar);
    }

    @Override // G0.x
    public int e(X.l lVar) {
        return this.f819a.e(lVar);
    }

    @Override // G0.x
    public AbstractC0311a get(Object obj) {
        AbstractC0311a abstractC0311a = this.f819a.get(obj);
        if (abstractC0311a == null) {
            this.f820b.c(obj);
        } else {
            this.f820b.b(obj);
        }
        return abstractC0311a;
    }
}
