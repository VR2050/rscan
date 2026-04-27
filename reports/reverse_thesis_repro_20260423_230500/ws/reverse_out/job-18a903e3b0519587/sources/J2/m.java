package J2;

import kotlin.jvm.internal.DefaultConstructorMarker;

/* JADX INFO: loaded from: classes.dex */
public final class m {

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    public static final a f1685c = new a(null);

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private int f1686a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final int[] f1687b = new int[10];

    public static final class a {
        private a() {
        }

        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }
    }

    public final int a(int i3) {
        return this.f1687b[i3];
    }

    public final int b() {
        if ((this.f1686a & 2) != 0) {
            return this.f1687b[1];
        }
        return -1;
    }

    public final int c() {
        if ((this.f1686a & 128) != 0) {
            return this.f1687b[7];
        }
        return 65535;
    }

    public final int d() {
        if ((this.f1686a & 16) != 0) {
            return this.f1687b[4];
        }
        return Integer.MAX_VALUE;
    }

    public final int e(int i3) {
        return (this.f1686a & 32) != 0 ? this.f1687b[5] : i3;
    }

    public final boolean f(int i3) {
        return ((1 << i3) & this.f1686a) != 0;
    }

    public final void g(m mVar) {
        t2.j.f(mVar, "other");
        for (int i3 = 0; i3 < 10; i3++) {
            if (mVar.f(i3)) {
                h(i3, mVar.a(i3));
            }
        }
    }

    public final m h(int i3, int i4) {
        if (i3 >= 0) {
            int[] iArr = this.f1687b;
            if (i3 < iArr.length) {
                this.f1686a = (1 << i3) | this.f1686a;
                iArr[i3] = i4;
            }
        }
        return this;
    }

    public final int i() {
        return Integer.bitCount(this.f1686a);
    }
}
