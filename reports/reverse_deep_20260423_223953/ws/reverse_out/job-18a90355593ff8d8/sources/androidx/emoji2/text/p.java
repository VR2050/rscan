package androidx.emoji2.text;

import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.Typeface;
import y.C0719a;

/* JADX INFO: loaded from: classes.dex */
public class p {

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private static final ThreadLocal f4685d = new ThreadLocal();

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final int f4686a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final n f4687b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private volatile int f4688c = 0;

    p(n nVar, int i3) {
        this.f4687b = nVar;
        this.f4686a = i3;
    }

    private C0719a g() {
        ThreadLocal threadLocal = f4685d;
        C0719a c0719a = (C0719a) threadLocal.get();
        if (c0719a == null) {
            c0719a = new C0719a();
            threadLocal.set(c0719a);
        }
        this.f4687b.d().j(c0719a, this.f4686a);
        return c0719a;
    }

    public void a(Canvas canvas, float f3, float f4, Paint paint) {
        Typeface typefaceG = this.f4687b.g();
        Typeface typeface = paint.getTypeface();
        paint.setTypeface(typefaceG);
        canvas.drawText(this.f4687b.c(), this.f4686a * 2, 2, f3, f4, paint);
        paint.setTypeface(typeface);
    }

    public int b(int i3) {
        return g().h(i3);
    }

    public int c() {
        return g().i();
    }

    public int d() {
        return this.f4688c & 3;
    }

    public int e() {
        return g().k();
    }

    public int f() {
        return g().l();
    }

    public short h() {
        return g().m();
    }

    public int i() {
        return g().n();
    }

    public boolean j() {
        return g().j();
    }

    public boolean k() {
        return (this.f4688c & 4) > 0;
    }

    public void l(boolean z3) {
        int iD = d();
        if (z3) {
            this.f4688c = iD | 4;
        } else {
            this.f4688c = iD;
        }
    }

    public void m(boolean z3) {
        int i3 = this.f4688c & 4;
        this.f4688c = z3 ? i3 | 2 : i3 | 1;
    }

    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(super.toString());
        sb.append(", id:");
        sb.append(Integer.toHexString(f()));
        sb.append(", codepoints:");
        int iC = c();
        for (int i3 = 0; i3 < iC; i3++) {
            sb.append(Integer.toHexString(b(i3)));
            sb.append(" ");
        }
        return sb.toString();
    }
}
