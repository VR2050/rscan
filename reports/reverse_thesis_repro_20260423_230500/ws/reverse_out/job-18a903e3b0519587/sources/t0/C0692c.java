package t0;

import android.graphics.Canvas;
import android.graphics.drawable.Drawable;
import s0.E;
import s0.F;
import s0.g;

/* JADX INFO: renamed from: t0.c, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public class C0692c extends g implements E {

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    Drawable f10163f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private F f10164g;

    public C0692c(Drawable drawable) {
        super(drawable);
        this.f10163f = null;
    }

    @Override // s0.g, android.graphics.drawable.Drawable
    public void draw(Canvas canvas) {
        if (isVisible()) {
            F f3 = this.f10164g;
            if (f3 != null) {
                f3.onDraw();
            }
            super.draw(canvas);
            Drawable drawable = this.f10163f;
            if (drawable != null) {
                drawable.setBounds(getBounds());
                this.f10163f.draw(canvas);
            }
        }
    }

    @Override // s0.g, android.graphics.drawable.Drawable
    public int getIntrinsicHeight() {
        return -1;
    }

    @Override // s0.g, android.graphics.drawable.Drawable
    public int getIntrinsicWidth() {
        return -1;
    }

    @Override // s0.E
    public void s(F f3) {
        this.f10164g = f3;
    }

    @Override // s0.g, android.graphics.drawable.Drawable
    public boolean setVisible(boolean z3, boolean z4) {
        F f3 = this.f10164g;
        if (f3 != null) {
            f3.i(z3);
        }
        return super.setVisible(z3, z4);
    }

    public void x(Drawable drawable) {
        this.f10163f = drawable;
        invalidateSelf();
    }
}
