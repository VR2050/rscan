package I0;

import android.util.Log;
import b0.AbstractC0311a;
import java.io.Closeable;

/* JADX INFO: renamed from: I0.a, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public class C0176a {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final AbstractC0311a.c f1188a;

    /* JADX INFO: renamed from: I0.a$a, reason: collision with other inner class name */
    class C0018a implements AbstractC0311a.c {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        final /* synthetic */ K0.a f1189a;

        C0018a(K0.a aVar) {
            this.f1189a = aVar;
        }

        @Override // b0.AbstractC0311a.c
        public boolean a() {
            return this.f1189a.b();
        }

        @Override // b0.AbstractC0311a.c
        public void b(b0.h hVar, Throwable th) {
            this.f1189a.a(hVar, th);
            Object objF = hVar.f();
            Y.a.K("Fresco", "Finalized without closing: %x %x (type = %s).\nStack:\n%s", Integer.valueOf(System.identityHashCode(this)), Integer.valueOf(System.identityHashCode(hVar)), objF != null ? objF.getClass().getName() : "<value is null>", C0176a.d(th));
        }
    }

    public C0176a(K0.a aVar) {
        this.f1188a = new C0018a(aVar);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static String d(Throwable th) {
        return th == null ? "" : Log.getStackTraceString(th);
    }

    public AbstractC0311a b(Closeable closeable) {
        return AbstractC0311a.f0(closeable, this.f1188a);
    }

    public AbstractC0311a c(Object obj, b0.g gVar) {
        return AbstractC0311a.t0(obj, gVar, this.f1188a);
    }
}
