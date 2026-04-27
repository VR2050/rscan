package l0;

import X.n;
import X.o;
import java.util.List;
import y0.InterfaceC0728g;

/* JADX INFO: renamed from: l0.b, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public class C0614b {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final X.f f9483a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final C0620h f9484b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final n f9485c;

    /* JADX INFO: renamed from: l0.b$a */
    public static final class a {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private List f9486a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private n f9487b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private C0620h f9488c;

        static /* bridge */ /* synthetic */ InterfaceC0728g c(a aVar) {
            aVar.getClass();
            return null;
        }

        public C0614b e() {
            return new C0614b(this);
        }
    }

    public static a e() {
        return new a();
    }

    public X.f a() {
        return this.f9483a;
    }

    public n b() {
        return this.f9485c;
    }

    public InterfaceC0728g c() {
        return null;
    }

    public C0620h d() {
        return this.f9484b;
    }

    private C0614b(a aVar) {
        this.f9483a = aVar.f9486a != null ? X.f.a(aVar.f9486a) : null;
        this.f9485c = aVar.f9487b != null ? aVar.f9487b : o.a(Boolean.FALSE);
        this.f9484b = aVar.f9488c;
        a.c(aVar);
    }
}
