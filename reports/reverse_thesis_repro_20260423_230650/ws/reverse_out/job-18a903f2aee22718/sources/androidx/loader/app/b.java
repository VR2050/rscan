package androidx.loader.app;

import androidx.activity.result.d;
import androidx.lifecycle.B;
import androidx.lifecycle.k;
import androidx.lifecycle.y;
import androidx.lifecycle.z;
import java.io.FileDescriptor;
import java.io.PrintWriter;
import l.h;
import q.AbstractC0652b;

/* JADX INFO: loaded from: classes.dex */
class b extends androidx.loader.app.a {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final k f5197a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final a f5198b;

    static class a extends y {

        /* JADX INFO: renamed from: f, reason: collision with root package name */
        private static final z.b f5199f = new C0079a();

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        private h f5200d = new h();

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        private boolean f5201e = false;

        /* JADX INFO: renamed from: androidx.loader.app.b$a$a, reason: collision with other inner class name */
        static class C0079a implements z.b {
            C0079a() {
            }

            @Override // androidx.lifecycle.z.b
            public y a(Class cls) {
                return new a();
            }
        }

        a() {
        }

        static a f(B b3) {
            return (a) new z(b3, f5199f).a(a.class);
        }

        @Override // androidx.lifecycle.y
        protected void d() {
            super.d();
            if (this.f5200d.n() <= 0) {
                this.f5200d.c();
            } else {
                d.a(this.f5200d.o(0));
                throw null;
            }
        }

        public void e(String str, FileDescriptor fileDescriptor, PrintWriter printWriter, String[] strArr) {
            if (this.f5200d.n() > 0) {
                printWriter.print(str);
                printWriter.println("Loaders:");
                StringBuilder sb = new StringBuilder();
                sb.append(str);
                sb.append("    ");
                if (this.f5200d.n() <= 0) {
                    return;
                }
                d.a(this.f5200d.o(0));
                printWriter.print(str);
                printWriter.print("  #");
                printWriter.print(this.f5200d.l(0));
                printWriter.print(": ");
                throw null;
            }
        }

        void g() {
            if (this.f5200d.n() <= 0) {
                return;
            }
            d.a(this.f5200d.o(0));
            throw null;
        }
    }

    b(k kVar, B b3) {
        this.f5197a = kVar;
        this.f5198b = a.f(b3);
    }

    @Override // androidx.loader.app.a
    public void a(String str, FileDescriptor fileDescriptor, PrintWriter printWriter, String[] strArr) {
        this.f5198b.e(str, fileDescriptor, printWriter, strArr);
    }

    @Override // androidx.loader.app.a
    public void c() {
        this.f5198b.g();
    }

    public String toString() {
        StringBuilder sb = new StringBuilder(128);
        sb.append("LoaderManager{");
        sb.append(Integer.toHexString(System.identityHashCode(this)));
        sb.append(" in ");
        AbstractC0652b.a(this.f5197a, sb);
        sb.append("}}");
        return sb.toString();
    }
}
