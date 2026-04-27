package d1;

/* JADX INFO: renamed from: d1.b, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public final class C0506b implements q.e {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final Object[] f9152a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private int f9153b;

    public C0506b(int i3) {
        this.f9152a = new Object[i3];
    }

    @Override // q.e
    public synchronized boolean a(Object obj) {
        t2.j.f(obj, "instance");
        int i3 = this.f9153b;
        Object[] objArr = this.f9152a;
        if (i3 == objArr.length) {
            return false;
        }
        objArr[i3] = obj;
        this.f9153b = i3 + 1;
        return true;
    }

    @Override // q.e
    public synchronized Object b() {
        int i3 = this.f9153b;
        if (i3 == 0) {
            return null;
        }
        int i4 = i3 - 1;
        this.f9153b = i4;
        Object obj = this.f9152a[i4];
        t2.j.d(obj, "null cannot be cast to non-null type T of com.facebook.react.common.ClearableSynchronizedPool");
        this.f9152a[i4] = null;
        return obj;
    }

    public final synchronized void c() {
        try {
            int i3 = this.f9153b;
            for (int i4 = 0; i4 < i3; i4++) {
                this.f9152a[i4] = null;
            }
            this.f9153b = 0;
        } catch (Throwable th) {
            throw th;
        }
    }
}
