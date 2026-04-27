package s0;

import android.graphics.Canvas;
import android.graphics.drawable.NinePatchDrawable;

/* JADX INFO: loaded from: classes.dex */
public final class n extends m {
    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public n(NinePatchDrawable ninePatchDrawable) {
        super(ninePatchDrawable);
        t2.j.f(ninePatchDrawable, "ninePatchDrawable");
    }

    @Override // s0.m, android.graphics.drawable.Drawable
    public void draw(Canvas canvas) {
        t2.j.f(canvas, "canvas");
        if (U0.b.d()) {
            U0.b.a("RoundedNinePatchDrawable#draw");
        }
        if (!f()) {
            super.draw(canvas);
            if (U0.b.d()) {
                U0.b.b();
                return;
            }
            return;
        }
        k();
        j();
        canvas.clipPath(this.f10086f);
        super.draw(canvas);
        if (U0.b.d()) {
            U0.b.b();
        }
    }
}
