package G0;

/* JADX INFO: loaded from: classes.dex */
public abstract class v {

    class a implements z {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        final /* synthetic */ t f821a;

        a(t tVar) {
            this.f821a = tVar;
        }

        @Override // G0.z
        /* JADX INFO: renamed from: d, reason: merged with bridge method [inline-methods] */
        public void b(R.d dVar) {
            this.f821a.k(dVar);
        }

        @Override // G0.z
        /* JADX INFO: renamed from: e, reason: merged with bridge method [inline-methods] */
        public void c(R.d dVar) {
            this.f821a.n(dVar);
        }

        @Override // G0.z
        /* JADX INFO: renamed from: f, reason: merged with bridge method [inline-methods] */
        public void a(R.d dVar) {
            this.f821a.j(dVar);
        }
    }

    public static u a(x xVar, t tVar) {
        tVar.l(xVar);
        return new u(xVar, new a(tVar));
    }
}
