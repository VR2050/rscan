package S;

import R.c;
import java.io.IOException;

/* JADX INFO: loaded from: classes.dex */
public class l implements R.b {

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private static final Object f2721i = new Object();

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private static l f2722j;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private static int f2723k;

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private R.d f2724a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private String f2725b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private long f2726c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private long f2727d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private long f2728e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private IOException f2729f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private c.a f2730g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private l f2731h;

    private l() {
    }

    public static l a() {
        synchronized (f2721i) {
            try {
                l lVar = f2722j;
                if (lVar == null) {
                    return new l();
                }
                f2722j = lVar.f2731h;
                lVar.f2731h = null;
                f2723k--;
                return lVar;
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    private void c() {
        this.f2724a = null;
        this.f2725b = null;
        this.f2726c = 0L;
        this.f2727d = 0L;
        this.f2728e = 0L;
        this.f2729f = null;
        this.f2730g = null;
    }

    public void b() {
        synchronized (f2721i) {
            try {
                if (f2723k < 5) {
                    c();
                    f2723k++;
                    l lVar = f2722j;
                    if (lVar != null) {
                        this.f2731h = lVar;
                    }
                    f2722j = this;
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public l d(R.d dVar) {
        this.f2724a = dVar;
        return this;
    }

    public l e(long j3) {
        this.f2727d = j3;
        return this;
    }

    public l f(long j3) {
        this.f2728e = j3;
        return this;
    }

    public l g(c.a aVar) {
        this.f2730g = aVar;
        return this;
    }

    public l h(IOException iOException) {
        this.f2729f = iOException;
        return this;
    }

    public l i(long j3) {
        this.f2726c = j3;
        return this;
    }

    public l j(String str) {
        this.f2725b = str;
        return this;
    }
}
