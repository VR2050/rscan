package N0;

import android.graphics.drawable.Drawable;

/* JADX INFO: loaded from: classes.dex */
public final class i extends g implements f {

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private Drawable f1881e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private boolean f1882f;

    public i(Drawable drawable) {
        this.f1881e = drawable;
    }

    @Override // N0.d
    public boolean a() {
        return this.f1882f;
    }

    @Override // N0.d
    public int b0() {
        return h() * d() * 4;
    }

    @Override // N0.d, java.io.Closeable, java.lang.AutoCloseable
    public void close() {
        this.f1881e = null;
        this.f1882f = true;
    }

    @Override // N0.d, N0.l
    public int d() {
        Drawable drawable = this.f1881e;
        if (drawable != null) {
            Integer numValueOf = Integer.valueOf(drawable.getIntrinsicHeight());
            if (numValueOf.intValue() < 0) {
                numValueOf = null;
            }
            if (numValueOf != null) {
                return numValueOf.intValue();
            }
        }
        return 0;
    }

    @Override // N0.f
    public Drawable g0() {
        Drawable.ConstantState constantState;
        Drawable drawable = this.f1881e;
        if (drawable == null || (constantState = drawable.getConstantState()) == null) {
            return null;
        }
        return constantState.newDrawable();
    }

    @Override // N0.d, N0.l
    public int h() {
        Drawable drawable = this.f1881e;
        if (drawable != null) {
            Integer numValueOf = Integer.valueOf(drawable.getIntrinsicWidth());
            if (numValueOf.intValue() < 0) {
                numValueOf = null;
            }
            if (numValueOf != null) {
                return numValueOf.intValue();
            }
        }
        return 0;
    }
}
