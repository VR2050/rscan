package p;

import android.graphics.Typeface;
import android.os.Handler;
import p.f;
import p.g;

/* JADX INFO: renamed from: p.a, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
class C0641a {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final g.c f9735a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final Handler f9736b;

    /* JADX INFO: renamed from: p.a$a, reason: collision with other inner class name */
    class RunnableC0143a implements Runnable {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ g.c f9737b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final /* synthetic */ Typeface f9738c;

        RunnableC0143a(g.c cVar, Typeface typeface) {
            this.f9737b = cVar;
            this.f9738c = typeface;
        }

        @Override // java.lang.Runnable
        public void run() {
            this.f9737b.b(this.f9738c);
        }
    }

    /* JADX INFO: renamed from: p.a$b */
    class b implements Runnable {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ g.c f9740b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final /* synthetic */ int f9741c;

        b(g.c cVar, int i3) {
            this.f9740b = cVar;
            this.f9741c = i3;
        }

        @Override // java.lang.Runnable
        public void run() {
            this.f9740b.a(this.f9741c);
        }
    }

    C0641a(g.c cVar, Handler handler) {
        this.f9735a = cVar;
        this.f9736b = handler;
    }

    private void a(int i3) {
        this.f9736b.post(new b(this.f9735a, i3));
    }

    private void c(Typeface typeface) {
        this.f9736b.post(new RunnableC0143a(this.f9735a, typeface));
    }

    void b(f.e eVar) {
        if (eVar.a()) {
            c(eVar.f9765a);
        } else {
            a(eVar.f9766b);
        }
    }
}
