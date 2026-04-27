package s0;

import android.graphics.Canvas;
import android.graphics.Matrix;
import android.graphics.Rect;
import android.graphics.RectF;
import android.graphics.drawable.Drawable;

/* JADX INFO: loaded from: classes.dex */
public final class h extends g {

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    public final Matrix f10030f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private final int f10031g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private final int f10032h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private final Matrix f10033i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private final RectF f10034j;

    public h(Drawable drawable, int i3, int i4) {
        super(drawable);
        this.f10030f = new Matrix();
        this.f10031g = i3 - (i3 % 90);
        this.f10032h = (i4 < 0 || i4 > 8) ? 0 : i4;
        this.f10033i = new Matrix();
        this.f10034j = new RectF();
    }

    @Override // s0.g, android.graphics.drawable.Drawable
    public void draw(Canvas canvas) {
        int i3;
        t2.j.f(canvas, "canvas");
        if (this.f10031g <= 0 && ((i3 = this.f10032h) == 0 || i3 == 1)) {
            super.draw(canvas);
            return;
        }
        int iSave = canvas.save();
        canvas.concat(this.f10030f);
        super.draw(canvas);
        canvas.restoreToCount(iSave);
    }

    @Override // s0.g, android.graphics.drawable.Drawable
    public int getIntrinsicHeight() {
        int i3 = this.f10032h;
        return (i3 == 5 || i3 == 7 || this.f10031g % 180 != 0) ? super.getIntrinsicWidth() : super.getIntrinsicHeight();
    }

    @Override // s0.g, android.graphics.drawable.Drawable
    public int getIntrinsicWidth() {
        int i3 = this.f10032h;
        return (i3 == 5 || i3 == 7 || this.f10031g % 180 != 0) ? super.getIntrinsicHeight() : super.getIntrinsicWidth();
    }

    @Override // s0.g, s0.D
    public void n(Matrix matrix) {
        t2.j.f(matrix, "transform");
        u(matrix);
        if (this.f10030f.isIdentity()) {
            return;
        }
        matrix.preConcat(this.f10030f);
    }

    @Override // s0.g, android.graphics.drawable.Drawable
    protected void onBoundsChange(Rect rect) {
        int i3;
        t2.j.f(rect, "bounds");
        Drawable current = getCurrent();
        if (current == null) {
            return;
        }
        int i4 = this.f10031g;
        if (i4 <= 0 && ((i3 = this.f10032h) == 0 || i3 == 1)) {
            current.setBounds(rect);
            return;
        }
        int i5 = this.f10032h;
        if (i5 == 2) {
            this.f10030f.setScale(-1.0f, 1.0f);
        } else if (i5 == 7) {
            this.f10030f.setRotate(270.0f, rect.centerX(), rect.centerY());
            this.f10030f.postScale(-1.0f, 1.0f);
        } else if (i5 == 4) {
            this.f10030f.setScale(1.0f, -1.0f);
        } else if (i5 != 5) {
            this.f10030f.setRotate(i4, rect.centerX(), rect.centerY());
        } else {
            this.f10030f.setRotate(270.0f, rect.centerX(), rect.centerY());
            this.f10030f.postScale(1.0f, -1.0f);
        }
        this.f10033i.reset();
        this.f10030f.invert(this.f10033i);
        this.f10034j.set(rect);
        this.f10033i.mapRect(this.f10034j);
        RectF rectF = this.f10034j;
        current.setBounds((int) rectF.left, (int) rectF.top, (int) rectF.right, (int) rectF.bottom);
    }
}
