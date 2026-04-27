package Y0;

import android.graphics.ColorSpace;
import h2.C0563i;

/* JADX INFO: loaded from: classes.dex */
public final class g {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final ColorSpace f2869a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final C0563i f2870b;

    public g(int i3, int i4, ColorSpace colorSpace) {
        this.f2869a = colorSpace;
        this.f2870b = (i3 == -1 || i4 == -1) ? null : new C0563i(Integer.valueOf(i3), Integer.valueOf(i4));
    }

    public final ColorSpace a() {
        return this.f2869a;
    }

    public final C0563i b() {
        return this.f2870b;
    }
}
