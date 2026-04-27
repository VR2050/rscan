package S;

import R.a;
import S.f;
import W.c;
import X.n;
import java.io.File;
import java.io.IOException;
import java.util.Collection;

/* JADX INFO: loaded from: classes.dex */
public class h implements f {

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private static final Class f2713f = h.class;

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final int f2714a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final n f2715b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final String f2716c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final R.a f2717d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    volatile a f2718e = new a(null, null);

    static class a {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        public final f f2719a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        public final File f2720b;

        a(File file, f fVar) {
            this.f2719a = fVar;
            this.f2720b = file;
        }
    }

    public h(int i3, n nVar, String str, R.a aVar) {
        this.f2714a = i3;
        this.f2717d = aVar;
        this.f2715b = nVar;
        this.f2716c = str;
    }

    private void l() throws c.a {
        File file = new File((File) this.f2715b.get(), this.f2716c);
        k(file);
        this.f2718e = new a(file, new S.a(file, this.f2714a, this.f2717d));
    }

    private boolean o() {
        File file;
        a aVar = this.f2718e;
        return aVar.f2719a == null || (file = aVar.f2720b) == null || !file.exists();
    }

    @Override // S.f
    public void a() {
        n().a();
    }

    @Override // S.f
    public Collection b() {
        return n().b();
    }

    @Override // S.f
    public boolean c() {
        try {
            return n().c();
        } catch (IOException unused) {
            return false;
        }
    }

    @Override // S.f
    public void d() {
        try {
            n().d();
        } catch (IOException e3) {
            Y.a.j(f2713f, "purgeUnexpectedResources", e3);
        }
    }

    @Override // S.f
    public long e(f.a aVar) {
        return n().e(aVar);
    }

    @Override // S.f
    public f.b f(String str, Object obj) {
        return n().f(str, obj);
    }

    @Override // S.f
    public boolean g(String str, Object obj) {
        return n().g(str, obj);
    }

    @Override // S.f
    public long h(String str) {
        return n().h(str);
    }

    @Override // S.f
    public boolean i(String str, Object obj) {
        return n().i(str, obj);
    }

    @Override // S.f
    public Q.a j(String str, Object obj) {
        return n().j(str, obj);
    }

    void k(File file) throws c.a {
        try {
            W.c.a(file);
            Y.a.a(f2713f, "Created cache directory %s", file.getAbsolutePath());
        } catch (c.a e3) {
            this.f2717d.a(a.EnumC0038a.WRITE_CREATE_DIR, f2713f, "createRootDirectoryIfNecessary", e3);
            throw e3;
        }
    }

    void m() {
        if (this.f2718e.f2719a == null || this.f2718e.f2720b == null) {
            return;
        }
        W.a.b(this.f2718e.f2720b);
    }

    synchronized f n() {
        try {
            if (o()) {
                m();
                l();
            }
        } catch (Throwable th) {
            throw th;
        }
        return (f) X.k.g(this.f2718e.f2719a);
    }
}
