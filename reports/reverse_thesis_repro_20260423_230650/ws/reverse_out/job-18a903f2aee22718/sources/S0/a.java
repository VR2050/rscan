package S0;

import R.d;
import R.i;
import X.k;
import android.graphics.Bitmap;
import com.facebook.imagepipeline.nativecode.NativeBlurFilter;

/* JADX INFO: loaded from: classes.dex */
public class a extends T0.a {

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final int f2732c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final int f2733d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private d f2734e;

    public a(int i3, int i4) {
        k.b(Boolean.valueOf(i3 > 0));
        k.b(Boolean.valueOf(i4 > 0));
        this.f2732c = i3;
        this.f2733d = i4;
    }

    @Override // T0.a, T0.d
    public d b() {
        if (this.f2734e == null) {
            this.f2734e = new i(String.format(null, "i%dr%d", Integer.valueOf(this.f2732c), Integer.valueOf(this.f2733d)));
        }
        return this.f2734e;
    }

    @Override // T0.a
    public void d(Bitmap bitmap) {
        NativeBlurFilter.a(bitmap, this.f2732c, this.f2733d);
    }
}
