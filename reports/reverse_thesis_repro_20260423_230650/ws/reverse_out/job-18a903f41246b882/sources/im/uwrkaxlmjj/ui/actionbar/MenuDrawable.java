package im.uwrkaxlmjj.ui.actionbar;

import android.graphics.Canvas;
import android.graphics.ColorFilter;
import android.graphics.Paint;
import android.graphics.drawable.Drawable;
import android.view.animation.DecelerateInterpolator;
import com.google.android.exoplayer2.extractor.ts.TsExtractor;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import org.webrtc.mozi.JavaScreenCapturer;

/* JADX INFO: loaded from: classes5.dex */
public class MenuDrawable extends Drawable {
    private boolean animationInProgress;
    private int currentAnimationTime;
    private float currentRotation;
    private float finalRotation;
    private long lastFrameTime;
    private boolean reverseAngle;
    private Paint paint = new Paint(1);
    private boolean rotateToBack = true;
    private DecelerateInterpolator interpolator = new DecelerateInterpolator();

    public MenuDrawable() {
        this.paint.setStrokeWidth(AndroidUtilities.dp(2.0f));
    }

    public void setRotateToBack(boolean value) {
        this.rotateToBack = value;
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
                this.currentAnimationTime = (int) (f2 * 300.0f);
            } else {
                this.currentAnimationTime = (int) ((1.0f - f2) * 300.0f);
            }
            this.lastFrameTime = System.currentTimeMillis();
            this.finalRotation = rotation;
        } else {
            this.currentRotation = rotation;
            this.finalRotation = rotation;
        }
        invalidateSelf();
    }

    @Override // android.graphics.drawable.Drawable
    public void draw(Canvas canvas) {
        float endYDiff;
        float endXDiff;
        float startYDiff;
        float startXDiff;
        if (this.currentRotation != this.finalRotation) {
            if (this.lastFrameTime != 0) {
                long dt = System.currentTimeMillis() - this.lastFrameTime;
                int i = (int) (((long) this.currentAnimationTime) + dt);
                this.currentAnimationTime = i;
                if (i >= 300) {
                    this.currentRotation = this.finalRotation;
                } else if (this.currentRotation < this.finalRotation) {
                    this.currentRotation = this.interpolator.getInterpolation(i / 300.0f) * this.finalRotation;
                } else {
                    this.currentRotation = 1.0f - this.interpolator.getInterpolation(i / 300.0f);
                }
            }
            long dt2 = System.currentTimeMillis();
            this.lastFrameTime = dt2;
            invalidateSelf();
        }
        canvas.save();
        canvas.translate(getIntrinsicWidth() / 2, getIntrinsicHeight() / 2);
        int color1 = Theme.getColor(Theme.key_actionBarDefaultIcon);
        if (this.rotateToBack) {
            canvas.rotate(this.currentRotation * (this.reverseAngle ? -180 : JavaScreenCapturer.DEGREE_180));
            this.paint.setColor(color1);
            canvas.drawLine(-AndroidUtilities.dp(9.0f), 0.0f, AndroidUtilities.dp(9.0f) - (AndroidUtilities.dp(3.0f) * this.currentRotation), 0.0f, this.paint);
            float endYDiff2 = (AndroidUtilities.dp(5.0f) * (1.0f - Math.abs(this.currentRotation))) - (AndroidUtilities.dp(0.5f) * Math.abs(this.currentRotation));
            float endXDiff2 = AndroidUtilities.dp(9.0f) - (AndroidUtilities.dp(2.5f) * Math.abs(this.currentRotation));
            float startYDiff2 = AndroidUtilities.dp(5.0f) + (AndroidUtilities.dp(2.0f) * Math.abs(this.currentRotation));
            endYDiff = endYDiff2;
            endXDiff = endXDiff2;
            startYDiff = startYDiff2;
            startXDiff = (-AndroidUtilities.dp(9.0f)) + (AndroidUtilities.dp(7.5f) * Math.abs(this.currentRotation));
        } else {
            float endYDiff3 = this.currentRotation;
            canvas.rotate(endYDiff3 * (this.reverseAngle ? -225 : TsExtractor.TS_STREAM_TYPE_E_AC3));
            int color2 = Theme.getColor(Theme.key_actionBarActionModeDefaultIcon);
            this.paint.setColor(AndroidUtilities.getOffsetColor(color1, color2, this.currentRotation, 1.0f));
            canvas.drawLine((AndroidUtilities.dp(1.0f) * this.currentRotation) + (-AndroidUtilities.dp(9.0f)), 0.0f, AndroidUtilities.dp(9.0f) - (AndroidUtilities.dp(1.0f) * this.currentRotation), 0.0f, this.paint);
            float endYDiff4 = (AndroidUtilities.dp(5.0f) * (1.0f - Math.abs(this.currentRotation))) - (AndroidUtilities.dp(0.5f) * Math.abs(this.currentRotation));
            float endXDiff3 = AndroidUtilities.dp(9.0f) - (AndroidUtilities.dp(9.0f) * Math.abs(this.currentRotation));
            float startYDiff3 = AndroidUtilities.dp(5.0f) + (AndroidUtilities.dp(3.0f) * Math.abs(this.currentRotation));
            endYDiff = endYDiff4;
            endXDiff = endXDiff3;
            startYDiff = startYDiff3;
            startXDiff = (-AndroidUtilities.dp(9.0f)) + (AndroidUtilities.dp(9.0f) * Math.abs(this.currentRotation));
        }
        float f = startXDiff;
        float f2 = endXDiff;
        canvas.drawLine(f, -startYDiff, f2, -endYDiff, this.paint);
        canvas.drawLine(f, startYDiff, f2, endYDiff, this.paint);
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
