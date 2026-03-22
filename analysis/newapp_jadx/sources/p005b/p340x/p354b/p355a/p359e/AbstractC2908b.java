package p005b.p340x.p354b.p355a.p359e;

import android.graphics.ColorFilter;
import android.graphics.Paint;
import android.graphics.drawable.Drawable;

/* renamed from: b.x.b.a.e.b */
/* loaded from: classes2.dex */
public abstract class AbstractC2908b extends Drawable {

    /* renamed from: c */
    public Paint f7977c;

    public AbstractC2908b() {
        Paint paint = new Paint();
        this.f7977c = paint;
        paint.setStyle(Paint.Style.FILL);
        this.f7977c.setAntiAlias(true);
        this.f7977c.setColor(-5592406);
    }

    @Override // android.graphics.drawable.Drawable
    public int getOpacity() {
        return -3;
    }

    @Override // android.graphics.drawable.Drawable
    public void setAlpha(int i2) {
        this.f7977c.setAlpha(i2);
    }

    @Override // android.graphics.drawable.Drawable
    public void setColorFilter(ColorFilter colorFilter) {
        this.f7977c.setColorFilter(colorFilter);
    }
}
