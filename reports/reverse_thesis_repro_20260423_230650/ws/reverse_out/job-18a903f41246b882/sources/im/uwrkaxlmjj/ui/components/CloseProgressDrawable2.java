package im.uwrkaxlmjj.ui.components;

import android.graphics.Canvas;
import android.graphics.ColorFilter;
import android.graphics.Paint;
import android.graphics.RectF;
import android.graphics.drawable.Drawable;
import android.view.animation.DecelerateInterpolator;
import im.uwrkaxlmjj.messenger.AndroidUtilities;

/* JADX INFO: loaded from: classes5.dex */
public class CloseProgressDrawable2 extends Drawable {
    private float angle;
    private boolean animating;
    private long lastFrameTime;
    private int side;
    private Paint paint = new Paint(1);
    private DecelerateInterpolator interpolator = new DecelerateInterpolator();
    private RectF rect = new RectF();

    public CloseProgressDrawable2() {
        this.paint.setColor(-1);
        this.paint.setStrokeWidth(AndroidUtilities.dp(2.0f));
        this.paint.setStrokeCap(Paint.Cap.ROUND);
        this.paint.setStyle(Paint.Style.STROKE);
        this.side = AndroidUtilities.dp(8.0f);
    }

    public void startAnimation() {
        this.animating = true;
        this.lastFrameTime = System.currentTimeMillis();
        invalidateSelf();
    }

    public void stopAnimation() {
        this.animating = false;
    }

    public boolean isAnimating() {
        return this.animating;
    }

    public void setColor(int value) {
        this.paint.setColor(value);
    }

    public void setSide(int value) {
        this.side = value;
    }

    @Override // android.graphics.drawable.Drawable
    public void draw(Canvas canvas) {
        float progress1;
        float progress2;
        float progress3;
        float progress4;
        long newTime = System.currentTimeMillis();
        long j = this.lastFrameTime;
        if (j != 0) {
            long dt = newTime - j;
            if (this.animating || this.angle != 0.0f) {
                float f = this.angle + ((360 * dt) / 500.0f);
                this.angle = f;
                if (!this.animating && f >= 720.0f) {
                    this.angle = 0.0f;
                } else {
                    this.angle = this.angle - (((int) (r3 / 720.0f)) * 720);
                }
                invalidateSelf();
            }
        }
        canvas.save();
        canvas.translate(getIntrinsicWidth() / 2, getIntrinsicHeight() / 2);
        canvas.rotate(-45.0f);
        float f2 = this.angle;
        if (f2 >= 0.0f && f2 < 90.0f) {
            float progress12 = 1.0f - (f2 / 90.0f);
            progress1 = progress12;
            progress2 = 1.0f;
            progress3 = 1.0f;
            progress4 = 0.0f;
        } else {
            float f3 = this.angle;
            if (f3 >= 90.0f && f3 < 180.0f) {
                float progress22 = 1.0f - ((f3 - 90.0f) / 90.0f);
                progress1 = 0.0f;
                progress2 = progress22;
                progress3 = 1.0f;
                progress4 = 0.0f;
            } else {
                float f4 = this.angle;
                if (f4 >= 180.0f && f4 < 270.0f) {
                    float progress32 = 1.0f - ((f4 - 180.0f) / 90.0f);
                    progress1 = 0.0f;
                    progress2 = 0.0f;
                    progress3 = progress32;
                    progress4 = 0.0f;
                } else {
                    float f5 = this.angle;
                    if (f5 >= 270.0f && f5 < 360.0f) {
                        float progress42 = (f5 - 270.0f) / 90.0f;
                        progress1 = 0.0f;
                        progress2 = 0.0f;
                        progress3 = 0.0f;
                        progress4 = progress42;
                    } else {
                        float f6 = this.angle;
                        if (f6 >= 360.0f && f6 < 450.0f) {
                            float progress43 = 1.0f - ((f6 - 360.0f) / 90.0f);
                            progress1 = 0.0f;
                            progress2 = 0.0f;
                            progress3 = 0.0f;
                            progress4 = progress43;
                        } else {
                            float f7 = this.angle;
                            if (f7 >= 450.0f && f7 < 540.0f) {
                                float progress13 = (f7 - 450.0f) / 90.0f;
                                progress1 = progress13;
                                progress2 = 0.0f;
                                progress3 = 0.0f;
                                progress4 = 0.0f;
                            } else {
                                float f8 = this.angle;
                                if (f8 >= 540.0f && f8 < 630.0f) {
                                    float progress23 = (f8 - 540.0f) / 90.0f;
                                    progress1 = 1.0f;
                                    progress2 = progress23;
                                    progress3 = 0.0f;
                                    progress4 = 0.0f;
                                } else {
                                    float f9 = this.angle;
                                    if (f9 >= 630.0f && f9 < 720.0f) {
                                        float progress33 = (f9 - 630.0f) / 90.0f;
                                        progress1 = 1.0f;
                                        progress2 = 1.0f;
                                        progress3 = progress33;
                                        progress4 = 0.0f;
                                    } else {
                                        progress1 = 1.0f;
                                        progress2 = 1.0f;
                                        progress3 = 1.0f;
                                        progress4 = 0.0f;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        if (progress1 != 0.0f) {
            canvas.drawLine(0.0f, 0.0f, 0.0f, this.side * progress1, this.paint);
        }
        if (progress2 != 0.0f) {
            canvas.drawLine((-this.side) * progress2, 0.0f, 0.0f, 0.0f, this.paint);
        }
        if (progress3 != 0.0f) {
            canvas.drawLine(0.0f, (-this.side) * progress3, 0.0f, 0.0f, this.paint);
        }
        if (progress4 != 1.0f) {
            int i = this.side;
            canvas.drawLine(i * progress4, 0.0f, i, 0.0f, this.paint);
        }
        canvas.restore();
        int cx = getBounds().centerX();
        int cy = getBounds().centerY();
        RectF rectF = this.rect;
        int i2 = this.side;
        rectF.set(cx - i2, cy - i2, cx + i2, cy + i2);
        RectF rectF2 = this.rect;
        float f10 = this.angle;
        float f11 = (f10 >= 360.0f ? f10 - 360.0f : 0.0f) - 45.0f;
        float f12 = this.angle;
        canvas.drawArc(rectF2, f11, f12 < 360.0f ? f12 : 720.0f - f12, false, this.paint);
        this.lastFrameTime = newTime;
    }

    @Override // android.graphics.drawable.Drawable
    public void setAlpha(int alpha) {
    }

    @Override // android.graphics.drawable.Drawable
    public void setColorFilter(ColorFilter cf) {
        this.paint.setColorFilter(cf);
    }

    @Override // android.graphics.drawable.Drawable
    public int getOpacity() {
        return -2;
    }

    @Override // android.graphics.drawable.Drawable
    public int getIntrinsicWidth() {
        return AndroidUtilities.dp(24.0f);
    }

    @Override // android.graphics.drawable.Drawable
    public int getIntrinsicHeight() {
        return AndroidUtilities.dp(24.0f);
    }
}
