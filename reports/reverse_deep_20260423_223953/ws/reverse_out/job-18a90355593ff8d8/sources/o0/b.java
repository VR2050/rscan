package o0;

import android.os.Handler;
import android.os.Looper;
import java.util.ArrayList;
import o0.AbstractC0637a;

/* JADX INFO: loaded from: classes.dex */
class b extends AbstractC0637a {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final Object f9688b = new Object();

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private final Runnable f9692f = new a();

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private ArrayList f9690d = new ArrayList();

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private ArrayList f9691e = new ArrayList();

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final Handler f9689c = new Handler(Looper.getMainLooper());

    class a implements Runnable {
        a() {
        }

        @Override // java.lang.Runnable
        public void run() {
            synchronized (b.this.f9688b) {
                ArrayList arrayList = b.this.f9691e;
                b bVar = b.this;
                bVar.f9691e = bVar.f9690d;
                b.this.f9690d = arrayList;
            }
            int size = b.this.f9691e.size();
            for (int i3 = 0; i3 < size; i3++) {
                ((AbstractC0637a.InterfaceC0141a) b.this.f9691e.get(i3)).a();
            }
            b.this.f9691e.clear();
        }
    }

    @Override // o0.AbstractC0637a
    public void a(AbstractC0637a.InterfaceC0141a interfaceC0141a) {
        synchronized (this.f9688b) {
            this.f9690d.remove(interfaceC0141a);
        }
    }

    @Override // o0.AbstractC0637a
    public void d(AbstractC0637a.InterfaceC0141a interfaceC0141a) {
        if (!AbstractC0637a.c()) {
            interfaceC0141a.a();
            return;
        }
        synchronized (this.f9688b) {
            try {
                if (this.f9690d.contains(interfaceC0141a)) {
                    return;
                }
                this.f9690d.add(interfaceC0141a);
                boolean z3 = true;
                if (this.f9690d.size() != 1) {
                    z3 = false;
                }
                if (z3) {
                    this.f9689c.post(this.f9692f);
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }
}
