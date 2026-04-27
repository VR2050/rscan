package androidx.core.graphics;

import android.graphics.Insets;
import android.graphics.Rect;

/* JADX INFO: loaded from: classes.dex */
public final class b {

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    public static final b f4320e = new b(0, 0, 0, 0);

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    public final int f4321a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    public final int f4322b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    public final int f4323c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    public final int f4324d;

    static class a {
        static Insets a(int i3, int i4, int i5, int i6) {
            return Insets.of(i3, i4, i5, i6);
        }
    }

    private b(int i3, int i4, int i5, int i6) {
        this.f4321a = i3;
        this.f4322b = i4;
        this.f4323c = i5;
        this.f4324d = i6;
    }

    public static b a(b bVar, b bVar2) {
        return b(Math.max(bVar.f4321a, bVar2.f4321a), Math.max(bVar.f4322b, bVar2.f4322b), Math.max(bVar.f4323c, bVar2.f4323c), Math.max(bVar.f4324d, bVar2.f4324d));
    }

    public static b b(int i3, int i4, int i5, int i6) {
        return (i3 == 0 && i4 == 0 && i5 == 0 && i6 == 0) ? f4320e : new b(i3, i4, i5, i6);
    }

    public static b c(Rect rect) {
        return b(rect.left, rect.top, rect.right, rect.bottom);
    }

    public static b d(Insets insets) {
        return b(insets.left, insets.top, insets.right, insets.bottom);
    }

    public Insets e() {
        return a.a(this.f4321a, this.f4322b, this.f4323c, this.f4324d);
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || b.class != obj.getClass()) {
            return false;
        }
        b bVar = (b) obj;
        return this.f4324d == bVar.f4324d && this.f4321a == bVar.f4321a && this.f4323c == bVar.f4323c && this.f4322b == bVar.f4322b;
    }

    public int hashCode() {
        return (((((this.f4321a * 31) + this.f4322b) * 31) + this.f4323c) * 31) + this.f4324d;
    }

    public String toString() {
        return "Insets{left=" + this.f4321a + ", top=" + this.f4322b + ", right=" + this.f4323c + ", bottom=" + this.f4324d + '}';
    }
}
