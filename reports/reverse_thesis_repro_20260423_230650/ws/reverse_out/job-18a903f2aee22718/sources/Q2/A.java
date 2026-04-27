package Q2;

import i2.AbstractC0580h;
import java.util.Arrays;
import kotlin.jvm.internal.DefaultConstructorMarker;

/* JADX INFO: loaded from: classes.dex */
public final class A {

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    public static final a f2506h = new a(null);

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    public final byte[] f2507a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    public int f2508b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    public int f2509c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    public boolean f2510d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    public boolean f2511e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    public A f2512f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    public A f2513g;

    public static final class a {
        private a() {
        }

        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }
    }

    public A() {
        this.f2507a = new byte[8192];
        this.f2511e = true;
        this.f2510d = false;
    }

    public final void a() {
        A a3 = this.f2513g;
        int i3 = 0;
        if (!(a3 != this)) {
            throw new IllegalStateException("cannot compact");
        }
        t2.j.c(a3);
        if (a3.f2511e) {
            int i4 = this.f2509c - this.f2508b;
            A a4 = this.f2513g;
            t2.j.c(a4);
            int i5 = 8192 - a4.f2509c;
            A a5 = this.f2513g;
            t2.j.c(a5);
            if (!a5.f2510d) {
                A a6 = this.f2513g;
                t2.j.c(a6);
                i3 = a6.f2508b;
            }
            if (i4 > i5 + i3) {
                return;
            }
            A a7 = this.f2513g;
            t2.j.c(a7);
            g(a7, i4);
            b();
            B.b(this);
        }
    }

    public final A b() {
        A a3 = this.f2512f;
        if (a3 == this) {
            a3 = null;
        }
        A a4 = this.f2513g;
        t2.j.c(a4);
        a4.f2512f = this.f2512f;
        A a5 = this.f2512f;
        t2.j.c(a5);
        a5.f2513g = this.f2513g;
        this.f2512f = null;
        this.f2513g = null;
        return a3;
    }

    public final A c(A a3) {
        t2.j.f(a3, "segment");
        a3.f2513g = this;
        a3.f2512f = this.f2512f;
        A a4 = this.f2512f;
        t2.j.c(a4);
        a4.f2513g = a3;
        this.f2512f = a3;
        return a3;
    }

    public final A d() {
        this.f2510d = true;
        return new A(this.f2507a, this.f2508b, this.f2509c, true, false);
    }

    public final A e(int i3) {
        A aC;
        if (!(i3 > 0 && i3 <= this.f2509c - this.f2508b)) {
            throw new IllegalArgumentException("byteCount out of range");
        }
        if (i3 >= 1024) {
            aC = d();
        } else {
            aC = B.c();
            byte[] bArr = this.f2507a;
            byte[] bArr2 = aC.f2507a;
            int i4 = this.f2508b;
            AbstractC0580h.g(bArr, bArr2, 0, i4, i4 + i3, 2, null);
        }
        aC.f2509c = aC.f2508b + i3;
        this.f2508b += i3;
        A a3 = this.f2513g;
        t2.j.c(a3);
        a3.c(aC);
        return aC;
    }

    public final A f() {
        byte[] bArr = this.f2507a;
        byte[] bArrCopyOf = Arrays.copyOf(bArr, bArr.length);
        t2.j.e(bArrCopyOf, "java.util.Arrays.copyOf(this, size)");
        return new A(bArrCopyOf, this.f2508b, this.f2509c, false, true);
    }

    public final void g(A a3, int i3) {
        t2.j.f(a3, "sink");
        if (!a3.f2511e) {
            throw new IllegalStateException("only owner can write");
        }
        int i4 = a3.f2509c;
        if (i4 + i3 > 8192) {
            if (a3.f2510d) {
                throw new IllegalArgumentException();
            }
            int i5 = a3.f2508b;
            if ((i4 + i3) - i5 > 8192) {
                throw new IllegalArgumentException();
            }
            byte[] bArr = a3.f2507a;
            AbstractC0580h.g(bArr, bArr, 0, i5, i4, 2, null);
            a3.f2509c -= a3.f2508b;
            a3.f2508b = 0;
        }
        byte[] bArr2 = this.f2507a;
        byte[] bArr3 = a3.f2507a;
        int i6 = a3.f2509c;
        int i7 = this.f2508b;
        AbstractC0580h.e(bArr2, bArr3, i6, i7, i7 + i3);
        a3.f2509c += i3;
        this.f2508b += i3;
    }

    public A(byte[] bArr, int i3, int i4, boolean z3, boolean z4) {
        t2.j.f(bArr, "data");
        this.f2507a = bArr;
        this.f2508b = i3;
        this.f2509c = i4;
        this.f2510d = z3;
        this.f2511e = z4;
    }
}
