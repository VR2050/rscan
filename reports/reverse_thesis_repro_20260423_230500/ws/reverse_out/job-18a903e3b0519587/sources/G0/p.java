package G0;

import android.net.Uri;

/* JADX INFO: loaded from: classes.dex */
public class p implements k {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private static p f815a = null;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private static boolean f816b = false;

    protected p() {
    }

    public static synchronized p f() {
        try {
            if (f815a == null) {
                f815a = new p();
            }
        } catch (Throwable th) {
            throw th;
        }
        return f815a;
    }

    @Override // G0.k
    public R.d a(T0.b bVar, Object obj) {
        return d(bVar, bVar.v(), obj);
    }

    @Override // G0.k
    public R.d b(T0.b bVar, Object obj) {
        R.d dVar;
        String name;
        T0.d dVarL = bVar.l();
        if (dVarL != null) {
            R.d dVarB = dVarL.b();
            name = dVarL.getClass().getName();
            dVar = dVarB;
        } else {
            dVar = null;
            name = null;
        }
        C0173b c0173b = new C0173b(e(bVar.v()).toString(), bVar.r(), bVar.t(), bVar.h(), dVar, name);
        if (f816b) {
            c0173b.d(null);
        } else {
            c0173b.d(obj);
        }
        return c0173b;
    }

    @Override // G0.k
    public R.d c(T0.b bVar, Object obj) {
        C0173b c0173b = new C0173b(e(bVar.v()).toString(), bVar.r(), bVar.t(), bVar.h(), null, null);
        if (f816b) {
            c0173b.d(null);
        } else {
            c0173b.d(obj);
        }
        return c0173b;
    }

    @Override // G0.k
    public R.d d(T0.b bVar, Uri uri, Object obj) {
        return new R.i(e(uri).toString());
    }

    protected Uri e(Uri uri) {
        return uri;
    }
}
