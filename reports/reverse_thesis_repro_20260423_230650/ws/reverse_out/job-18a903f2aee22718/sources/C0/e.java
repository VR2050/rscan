package C0;

import C0.c;
import X.p;
import h2.AbstractC0558d;
import h2.EnumC0561g;
import java.io.IOException;
import java.io.InputStream;
import java.util.Iterator;
import java.util.List;
import kotlin.Lazy;
import kotlin.jvm.internal.DefaultConstructorMarker;
import s2.InterfaceC0688a;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public final class e {

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    public static final a f568e = new a(null);

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private static final Lazy f569f = AbstractC0558d.a(EnumC0561g.f9269b, new InterfaceC0688a() { // from class: C0.d
        @Override // s2.InterfaceC0688a
        public final Object a() {
            return e.f();
        }
    });

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private int f570a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private List f571b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final C0.a f572c = new C0.a();

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private boolean f573d;

    public static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        /* JADX INFO: Access modifiers changed from: private */
        public final int e(int i3, InputStream inputStream, byte[] bArr) throws IOException {
            if (bArr.length < i3) {
                throw new IllegalStateException("Check failed.");
            }
            if (!inputStream.markSupported()) {
                return X.a.b(inputStream, bArr, 0, i3);
            }
            try {
                inputStream.mark(i3);
                return X.a.b(inputStream, bArr, 0, i3);
            } finally {
                inputStream.reset();
            }
        }

        public final c b(InputStream inputStream) {
            j.f(inputStream, "is");
            return d().c(inputStream);
        }

        public final c c(InputStream inputStream) {
            j.f(inputStream, "is");
            try {
                return b(inputStream);
            } catch (IOException e3) {
                throw p.a(e3);
            }
        }

        public final e d() {
            return (e) e.f569f.getValue();
        }

        private a() {
        }
    }

    private e() {
        h();
    }

    public static final c d(InputStream inputStream) {
        return f568e.c(inputStream);
    }

    public static final e e() {
        return f568e.d();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final e f() {
        return new e();
    }

    private final void h() {
        this.f570a = this.f572c.a();
        List list = this.f571b;
        if (list != null) {
            j.c(list);
            Iterator it = list.iterator();
            while (it.hasNext()) {
                this.f570a = Math.max(this.f570a, ((c.b) it.next()).a());
            }
        }
    }

    public final c c(InputStream inputStream) throws IOException {
        j.f(inputStream, "is");
        int i3 = this.f570a;
        byte[] bArr = new byte[i3];
        int iE = f568e.e(i3, inputStream, bArr);
        c cVarB = this.f572c.b(bArr, iE);
        if (j.b(cVarB, b.f561n) && !this.f573d) {
            cVarB = c.f565d;
        }
        if (cVarB != c.f565d) {
            return cVarB;
        }
        List list = this.f571b;
        if (list != null) {
            Iterator it = list.iterator();
            while (it.hasNext()) {
                c cVarB2 = ((c.b) it.next()).b(bArr, iE);
                if (cVarB2 != c.f565d) {
                    return cVarB2;
                }
            }
        }
        return c.f565d;
    }

    public final e g(boolean z3) {
        this.f573d = z3;
        return this;
    }
}
