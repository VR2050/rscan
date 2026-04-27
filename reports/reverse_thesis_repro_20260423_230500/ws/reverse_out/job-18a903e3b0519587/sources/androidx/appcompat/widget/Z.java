package androidx.appcompat.widget;

/* JADX INFO: loaded from: classes.dex */
class Z {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private int f3940a = 0;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private int f3941b = 0;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private int f3942c = Integer.MIN_VALUE;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private int f3943d = Integer.MIN_VALUE;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private int f3944e = 0;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private int f3945f = 0;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private boolean f3946g = false;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private boolean f3947h = false;

    Z() {
    }

    public int a() {
        return this.f3946g ? this.f3940a : this.f3941b;
    }

    public int b() {
        return this.f3940a;
    }

    public int c() {
        return this.f3941b;
    }

    public int d() {
        return this.f3946g ? this.f3941b : this.f3940a;
    }

    public void e(int i3, int i4) {
        this.f3947h = false;
        if (i3 != Integer.MIN_VALUE) {
            this.f3944e = i3;
            this.f3940a = i3;
        }
        if (i4 != Integer.MIN_VALUE) {
            this.f3945f = i4;
            this.f3941b = i4;
        }
    }

    public void f(boolean z3) {
        if (z3 == this.f3946g) {
            return;
        }
        this.f3946g = z3;
        if (!this.f3947h) {
            this.f3940a = this.f3944e;
            this.f3941b = this.f3945f;
            return;
        }
        if (z3) {
            int i3 = this.f3943d;
            if (i3 == Integer.MIN_VALUE) {
                i3 = this.f3944e;
            }
            this.f3940a = i3;
            int i4 = this.f3942c;
            if (i4 == Integer.MIN_VALUE) {
                i4 = this.f3945f;
            }
            this.f3941b = i4;
            return;
        }
        int i5 = this.f3942c;
        if (i5 == Integer.MIN_VALUE) {
            i5 = this.f3944e;
        }
        this.f3940a = i5;
        int i6 = this.f3943d;
        if (i6 == Integer.MIN_VALUE) {
            i6 = this.f3945f;
        }
        this.f3941b = i6;
    }

    public void g(int i3, int i4) {
        this.f3942c = i3;
        this.f3943d = i4;
        this.f3947h = true;
        if (this.f3946g) {
            if (i4 != Integer.MIN_VALUE) {
                this.f3940a = i4;
            }
            if (i3 != Integer.MIN_VALUE) {
                this.f3941b = i3;
                return;
            }
            return;
        }
        if (i3 != Integer.MIN_VALUE) {
            this.f3940a = i3;
        }
        if (i4 != Integer.MIN_VALUE) {
            this.f3941b = i4;
        }
    }
}
