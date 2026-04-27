package s0;

import android.graphics.Canvas;
import android.graphics.Rect;
import android.graphics.drawable.Drawable;
import android.os.SystemClock;

/* JADX INFO: renamed from: s0.b, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public class RunnableC0682b extends g implements Runnable {

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private int f9999f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private boolean f10000g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    float f10001h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private boolean f10002i;

    public RunnableC0682b(Drawable drawable, int i3) {
        this(drawable, i3, true);
    }

    private int x() {
        return (int) ((20.0f / this.f9999f) * 360.0f);
    }

    private void y() {
        if (this.f10002i) {
            return;
        }
        this.f10002i = true;
        scheduleSelf(this, SystemClock.uptimeMillis() + 20);
    }

    @Override // s0.g, android.graphics.drawable.Drawable
    public void draw(Canvas canvas) {
        int iSave = canvas.save();
        Rect bounds = getBounds();
        int i3 = bounds.right - bounds.left;
        int i4 = bounds.bottom - bounds.top;
        float f3 = this.f10001h;
        if (!this.f10000g) {
            f3 = 360.0f - f3;
        }
        canvas.rotate(f3, r3 + (i3 / 2), r1 + (i4 / 2));
        super.draw(canvas);
        canvas.restoreToCount(iSave);
        y();
    }

    @Override // java.lang.Runnable
    public void run() {
        this.f10002i = false;
        this.f10001h += x();
        invalidateSelf();
    }

    public RunnableC0682b(Drawable drawable, int i3, boolean z3) {
        super((Drawable) X.k.g(drawable));
        this.f10001h = 0.0f;
        this.f10002i = false;
        this.f9999f = i3;
        this.f10000g = z3;
    }
}
