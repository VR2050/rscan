package p005b.p340x.p341a.p343b.p344a;

import android.graphics.Canvas;
import android.graphics.Path;
import android.graphics.Rect;
import androidx.annotation.NonNull;
import com.google.android.material.behavior.HideBottomViewOnScrollBehavior;
import p005b.p340x.p341a.p342a.AbstractC2865a;

/* renamed from: b.x.a.b.a.a */
/* loaded from: classes2.dex */
public class C2867a extends AbstractC2865a {

    /* renamed from: e */
    public int f7808e = 0;

    /* renamed from: f */
    public int f7809f = 0;

    /* renamed from: g */
    public final Path f7810g = new Path();

    @Override // android.graphics.drawable.Drawable
    public void draw(@NonNull Canvas canvas) {
        Rect bounds = getBounds();
        int width = bounds.width();
        int height = bounds.height();
        if (this.f7808e != width || this.f7809f != height) {
            int i2 = (width * 30) / HideBottomViewOnScrollBehavior.ENTER_ANIMATION_DURATION;
            this.f7810g.reset();
            float f2 = i2;
            float f3 = f2 * 0.70710677f;
            float f4 = f2 / 0.70710677f;
            float f5 = width;
            float f6 = f5 / 2.0f;
            float f7 = height;
            this.f7810g.moveTo(f6, f7);
            float f8 = f7 / 2.0f;
            this.f7810g.lineTo(0.0f, f8);
            float f9 = f8 - f3;
            this.f7810g.lineTo(f3, f9);
            float f10 = f2 / 2.0f;
            float f11 = f6 - f10;
            float f12 = (f7 - f4) - f10;
            this.f7810g.lineTo(f11, f12);
            this.f7810g.lineTo(f11, 0.0f);
            float f13 = f6 + f10;
            this.f7810g.lineTo(f13, 0.0f);
            this.f7810g.lineTo(f13, f12);
            this.f7810g.lineTo(f5 - f3, f9);
            this.f7810g.lineTo(f5, f8);
            this.f7810g.close();
            this.f7808e = width;
            this.f7809f = height;
        }
        canvas.drawPath(this.f7810g, this.f7802c);
    }
}
