package o0;

/* JADX INFO: loaded from: classes.dex */
public class d {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private boolean f9722a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private int f9723b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private int f9724c;

    public d() {
        a();
    }

    public void a() {
        this.f9722a = false;
        this.f9723b = 4;
        c();
    }

    public void b() {
        this.f9724c++;
    }

    public void c() {
        this.f9724c = 0;
    }

    public void d(boolean z3) {
        this.f9722a = z3;
    }

    public boolean e() {
        return this.f9722a && this.f9724c < this.f9723b;
    }
}
