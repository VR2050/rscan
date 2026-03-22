package p005b.p327w.p330b.p338e.p339b;

import android.graphics.Canvas;
import android.graphics.ColorFilter;
import android.graphics.Paint;
import android.graphics.RectF;
import android.graphics.drawable.Drawable;
import androidx.annotation.IntRange;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

/* renamed from: b.w.b.e.b.a */
/* loaded from: classes2.dex */
public final class C2864a extends Drawable {

    /* renamed from: a */
    public final int f7798a;

    /* renamed from: b */
    public final float f7799b;

    /* renamed from: c */
    @NotNull
    public final Paint f7800c;

    /* renamed from: d */
    @NotNull
    public final RectF f7801d;

    public C2864a(int i2, float f2) {
        this.f7798a = i2;
        this.f7799b = f2;
        Paint paint = new Paint();
        this.f7800c = paint;
        paint.setStyle(Paint.Style.FILL);
        paint.setAntiAlias(true);
        paint.setColor(i2);
        this.f7801d = new RectF();
    }

    /* renamed from: a */
    public final void m3307a(int i2, int i3) {
        RectF rectF = this.f7801d;
        rectF.left = 0.0f;
        rectF.top = 0.0f;
        rectF.right = i2;
        rectF.bottom = i3;
    }

    @Override // android.graphics.drawable.Drawable
    public void draw(@NotNull Canvas canvas) {
        Intrinsics.checkNotNullParameter(canvas, "canvas");
        float f2 = this.f7799b;
        if (f2 == 0.0f) {
            canvas.drawRect(this.f7801d, this.f7800c);
        } else {
            canvas.drawRoundRect(this.f7801d, f2, f2, this.f7800c);
        }
    }

    @Override // android.graphics.drawable.Drawable
    public int getOpacity() {
        return -3;
    }

    @Override // android.graphics.drawable.Drawable
    public void setAlpha(@IntRange(from = 0, m111to = 255) int i2) {
        this.f7800c.setAlpha(i2);
        invalidateSelf();
    }

    @Override // android.graphics.drawable.Drawable
    public void setColorFilter(@Nullable ColorFilter colorFilter) {
        this.f7800c.setColorFilter(colorFilter);
        invalidateSelf();
    }
}
