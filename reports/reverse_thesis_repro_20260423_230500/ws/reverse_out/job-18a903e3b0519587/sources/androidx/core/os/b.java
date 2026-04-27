package androidx.core.os;

import android.os.CancellationSignal;

/* JADX INFO: loaded from: classes.dex */
public final class b {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private boolean f4364a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private a f4365b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private Object f4366c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private boolean f4367d;

    public interface a {
        void a();
    }

    private void c() {
        while (this.f4367d) {
            try {
                wait();
            } catch (InterruptedException unused) {
            }
        }
    }

    public void a() {
        synchronized (this) {
            try {
                if (this.f4364a) {
                    return;
                }
                this.f4364a = true;
                this.f4367d = true;
                a aVar = this.f4365b;
                Object obj = this.f4366c;
                if (aVar != null) {
                    try {
                        aVar.a();
                    } catch (Throwable th) {
                        synchronized (this) {
                            this.f4367d = false;
                            notifyAll();
                            throw th;
                        }
                    }
                }
                if (obj != null) {
                    ((CancellationSignal) obj).cancel();
                }
                synchronized (this) {
                    this.f4367d = false;
                    notifyAll();
                }
            } finally {
            }
        }
    }

    public void b(a aVar) {
        synchronized (this) {
            try {
                c();
                if (this.f4365b == aVar) {
                    return;
                }
                this.f4365b = aVar;
                if (this.f4364a && aVar != null) {
                    aVar.a();
                }
            } finally {
            }
        }
    }
}
