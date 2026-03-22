package p005b.p340x.p341a.p342a;

import android.graphics.ColorFilter;
import android.graphics.Paint;
import android.graphics.drawable.Drawable;

/* renamed from: b.x.a.a.a */
/* loaded from: classes2.dex */
public abstract class AbstractC2865a extends Drawable {

    /* renamed from: c */
    public Paint f7802c;

    public AbstractC2865a() {
        Paint paint = new Paint();
        this.f7802c = paint;
        paint.setStyle(Paint.Style.FILL);
        this.f7802c.setAntiAlias(true);
        this.f7802c.setColor(-5592406);
    }

    @Override // android.graphics.drawable.Drawable
    public int getOpacity() {
        return -3;
    }

    @Override // android.graphics.drawable.Drawable
    public void setAlpha(int i2) {
        this.f7802c.setAlpha(i2);
    }

    @Override // android.graphics.drawable.Drawable
    public void setColorFilter(ColorFilter colorFilter) {
        this.f7802c.setColorFilter(colorFilter);
    }
}
