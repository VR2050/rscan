package im.uwrkaxlmjj.ui.actionbar;

import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.ColorFilter;
import android.graphics.Paint;
import android.graphics.drawable.Drawable;
import android.view.animation.DecelerateInterpolator;
import com.google.android.exoplayer2.extractor.ts.TsExtractor;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import org.webrtc.mozi.JavaScreenCapturer;

/* JADX INFO: loaded from: classes5.dex */
public class BackDrawable extends Drawable {
    private boolean alwaysClose;
    private boolean animationInProgress;
    private int arrowRotation;
    private int currentAnimationTime;
    private float currentRotation;
    private float finalRotation;
    private long lastFrameTime;
    private boolean reverseAngle;
    private Paint paint = new Paint(1);
    private DecelerateInterpolator interpolator = new DecelerateInterpolator();
    private int color = -1;
    private int rotatedColor = -9079435;
    private float animationTime = 300.0f;
    private boolean rotated = true;

    public BackDrawable(boolean close) {
        this.paint.setStrokeWidth(AndroidUtilities.dp(2.0f));
        this.alwaysClose = close;
    }

    public void setColor(int value) {
        this.color = value;
        invalidateSelf();
    }

    public void setRotatedColor(int value) {
        this.rotatedColor = value;
        invalidateSelf();
    }

    public void setArrowRotation(int angle) {
        this.arrowRotation = angle;
        invalidateSelf();
    }

    public void setRotation(float rotation, boolean animated) {
        this.lastFrameTime = 0L;
        float f = this.currentRotation;
        if (f == 1.0f) {
            this.reverseAngle = true;
        } else if (f == 0.0f) {
            this.reverseAngle = false;
        }
        this.lastFrameTime = 0L;
        if (animated) {
            float f2 = this.currentRotation;
            if (f2 < rotation) {
                this.currentAnimationTime = (int) (f2 * this.animationTime);
            } else {
                this.currentAnimationTime = (int) ((1.0f - f2) * this.animationTime);
            }
            this.lastFrameTime = System.currentTimeMillis();
            this.finalRotation = rotation;
        } else {
            this.currentRotation = rotation;
            this.finalRotation = rotation;
        }
        invalidateSelf();
    }

    public void setAnimationTime(float value) {
        this.animationTime = value;
    }

    public void setRotated(boolean value) {
        this.rotated = value;
    }

    @Override // android.graphics.drawable.Drawable
    public void draw(Canvas canvas) {
        float rotation;
        if (this.currentRotation != this.finalRotation) {
            if (this.lastFrameTime != 0) {
                long dt = System.currentTimeMillis() - this.lastFrameTime;
                int i = (int) (((long) this.currentAnimationTime) + dt);
                this.currentAnimationTime = i;
                float f = i;
                float f2 = this.animationTime;
                if (f >= f2) {
                    this.currentRotation = this.finalRotation;
                } else if (this.currentRotation < this.finalRotation) {
                    this.currentRotation = this.interpolator.getInterpolation(i / f2) * this.finalRotation;
                } else {
                    this.currentRotation = 1.0f - this.interpolator.getInterpolation(i / f2);
                }
            }
            long dt2 = System.currentTimeMillis();
            this.lastFrameTime = dt2;
            invalidateSelf();
        }
        int rD = this.rotated ? (int) ((Color.red(this.rotatedColor) - Color.red(this.color)) * this.currentRotation) : 0;
        int rG = this.rotated ? (int) ((Color.green(this.rotatedColor) - Color.green(this.color)) * this.currentRotation) : 0;
        int rB = this.rotated ? (int) ((Color.blue(this.rotatedColor) - Color.blue(this.color)) * this.currentRotation) : 0;
        int c = Color.rgb(Color.red(this.color) + rD, Color.green(this.color) + rG, Color.blue(this.color) + rB);
        this.paint.setColor(c);
        canvas.save();
        canvas.translate(getIntrinsicWidth() / 2, getIntrinsicHeight() / 2);
        int i2 = this.arrowRotation;
        if (i2 != 0) {
            canvas.rotate(i2);
        }
        float rotation2 = this.currentRotation;
        if (this.alwaysClose) {
            canvas.rotate((this.currentRotation * (this.reverseAngle ? -180 : JavaScreenCapturer.DEGREE_180)) + 135.0f);
            rotation = 1.0f;
        } else {
            canvas.rotate(this.currentRotation * (this.reverseAngle ? -225 : TsExtractor.TS_STREAM_TYPE_E_AC3));
            rotation = rotation2;
        }
        canvas.drawLine((-AndroidUtilities.dp(7.0f)) - (AndroidUtilities.dp(1.0f) * rotation), 0.0f, AndroidUtilities.dp(8.0f), 0.0f, this.paint);
        float startYDiff = -AndroidUtilities.dp(0.5f);
        float endYDiff = AndroidUtilities.dp(7.0f) + (AndroidUtilities.dp(1.0f) * rotation);
        float startXDiff = (-AndroidUtilities.dp(7.0f)) + (AndroidUtilities.dp(7.0f) * rotation);
        float endXDiff = AndroidUtilities.dp(0.5f) - (AndroidUtilities.dp(0.5f) * rotation);
        canvas.drawLine(startXDiff, -startYDiff, endXDiff, -endYDiff, this.paint);
        canvas.drawLine(startXDiff, startYDiff, endXDiff, endYDiff, this.paint);
        canvas.restore();
    }

    @Override // android.graphics.drawable.Drawable
    public void setAlpha(int alpha) {
    }

    @Override // android.graphics.drawable.Drawable
    public void setColorFilter(ColorFilter cf) {
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
