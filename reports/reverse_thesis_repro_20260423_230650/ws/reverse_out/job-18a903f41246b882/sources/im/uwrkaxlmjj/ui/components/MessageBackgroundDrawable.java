package im.uwrkaxlmjj.ui.components;

import android.graphics.Canvas;
import android.graphics.ColorFilter;
import android.graphics.Paint;
import android.graphics.drawable.Drawable;
import android.os.SystemClock;

/* JADX INFO: loaded from: classes5.dex */
public class MessageBackgroundDrawable extends Drawable {
    public static final float ANIMATION_DURATION = 200.0f;
    private boolean animationInProgress;
    private float currentAnimationProgress;
    private int finalRadius;
    private boolean isSelected;
    private long lastAnimationTime;
    private Paint paint;
    private float touchX;
    private float touchY;

    public MessageBackgroundDrawable(int color) {
        Paint paint = new Paint(1);
        this.paint = paint;
        this.touchX = -1.0f;
        this.touchY = -1.0f;
        paint.setColor(color);
    }

    public void setColor(int color) {
        this.paint.setColor(color);
    }

    public void setSelected(boolean selected, boolean animated) {
        if (this.isSelected == selected) {
            if (this.animationInProgress && 0 == 0) {
                this.currentAnimationProgress = selected ? 1.0f : 0.0f;
                this.animationInProgress = false;
                return;
            }
            return;
        }
        this.isSelected = selected;
        this.animationInProgress = false;
        if (0 != 0) {
            this.lastAnimationTime = SystemClock.uptimeMillis();
        } else {
            this.currentAnimationProgress = selected ? 1.0f : 0.0f;
        }
        calcRadius();
        invalidateSelf();
    }

    private void calcRadius() {
        float x1;
        float y1;
        float x2;
        int i;
        android.graphics.Rect bounds = getBounds();
        if (this.touchX >= 0.0f && this.touchY >= 0.0f) {
            x1 = this.touchX;
            y1 = this.touchY;
        } else {
            x1 = bounds.centerX();
            y1 = bounds.centerY();
        }
        this.finalRadius = 0;
        for (int a = 0; a < 4; a++) {
            if (a == 0) {
                x2 = bounds.left;
                i = bounds.top;
            } else if (a == 1) {
                x2 = bounds.left;
                i = bounds.bottom;
            } else if (a == 2) {
                x2 = bounds.right;
                i = bounds.top;
            } else {
                x2 = bounds.right;
                i = bounds.bottom;
            }
            float y2 = i;
            this.finalRadius = Math.max(this.finalRadius, (int) Math.ceil(Math.sqrt(((x2 - x1) * (x2 - x1)) + ((y2 - y1) * (y2 - y1)))));
        }
    }

    public void setTouchCoords(float x, float y) {
        this.touchX = x;
        this.touchY = y;
        calcRadius();
        invalidateSelf();
    }

    @Override // android.graphics.drawable.Drawable
    public void setBounds(int left, int top, int right, int bottom) {
        super.setBounds(left, top, right, bottom);
        calcRadius();
    }

    @Override // android.graphics.drawable.Drawable
    public void setBounds(android.graphics.Rect bounds) {
        super.setBounds(bounds);
        calcRadius();
    }

    @Override // android.graphics.drawable.Drawable
    public void setColorFilter(ColorFilter colorFilter) {
        this.paint.setColorFilter(colorFilter);
    }

    @Override // android.graphics.drawable.Drawable
    public int getOpacity() {
        return -2;
    }

    @Override // android.graphics.drawable.Drawable
    public void setAlpha(int alpha) {
        this.paint.setAlpha(alpha);
    }

    @Override // android.graphics.drawable.Drawable
    public void draw(Canvas canvas) {
        float x1;
        float x12;
        if (this.animationInProgress) {
            long newTime = SystemClock.uptimeMillis();
            long dt = newTime - this.lastAnimationTime;
            this.lastAnimationTime = newTime;
            if (this.isSelected) {
                float f = this.currentAnimationProgress + (dt / 200.0f);
                this.currentAnimationProgress = f;
                if (f >= 1.0f) {
                    this.touchX = -1.0f;
                    this.touchY = -1.0f;
                    this.currentAnimationProgress = 1.0f;
                    this.animationInProgress = false;
                }
                invalidateSelf();
            } else {
                float f2 = this.currentAnimationProgress - (dt / 200.0f);
                this.currentAnimationProgress = f2;
                if (f2 <= 0.0f) {
                    this.touchX = -1.0f;
                    this.touchY = -1.0f;
                    this.currentAnimationProgress = 0.0f;
                    this.animationInProgress = false;
                }
                invalidateSelf();
            }
        }
        float f3 = this.currentAnimationProgress;
        if (f3 == 1.0f) {
            canvas.drawRect(getBounds(), this.paint);
            return;
        }
        if (f3 != 0.0f) {
            if (this.touchX >= 0.0f && this.touchY >= 0.0f) {
                x1 = this.touchX;
                x12 = this.touchY;
            } else {
                android.graphics.Rect bounds = getBounds();
                float x13 = bounds.centerX();
                float fCenterY = bounds.centerY();
                x1 = x13;
                x12 = fCenterY;
            }
            canvas.drawCircle(x1, x12, this.finalRadius * CubicBezierInterpolator.EASE_OUT.getInterpolation(this.currentAnimationProgress), this.paint);
        }
    }
}
