package G0;

/* JADX INFO: loaded from: classes.dex */
public abstract class s {

    class a implements z {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        final /* synthetic */ t f818a;

        a(t tVar) {
            this.f818a = tVar;
        }

        @Override // G0.z
        /* JADX INFO: renamed from: d, reason: merged with bridge method [inline-methods] */
        public void b(R.d dVar) {
            this.f818a.h(dVar);
        }

        @Override // G0.z
        /* JADX INFO: renamed from: e, reason: merged with bridge method [inline-methods] */
        public void c(R.d dVar) {
            this.f818a.a(dVar);
        }

        @Override // G0.z
        /* JADX INFO: renamed from: f, reason: merged with bridge method [inline-methods] */
        public void a(R.d dVar) {
            this.f818a.g(dVar);
        }
    }

    public static u a(x xVar, t tVar) {
        tVar.c(xVar);
        return new u(xVar, new a(tVar));
    }
}
