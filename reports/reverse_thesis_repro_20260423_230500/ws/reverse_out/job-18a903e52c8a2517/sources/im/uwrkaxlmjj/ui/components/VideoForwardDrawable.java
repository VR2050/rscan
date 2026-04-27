package im.uwrkaxlmjj.ui.components;

import android.graphics.Canvas;
import android.graphics.ColorFilter;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.drawable.Drawable;
import im.uwrkaxlmjj.messenger.AndroidUtilities;

/* JADX INFO: loaded from: classes5.dex */
public class VideoForwardDrawable extends Drawable {
    private static final int[] playPath = {10, 7, 26, 16, 10, 25};
    private boolean animating;
    private float animationProgress;
    private VideoForwardDrawableDelegate delegate;
    private long lastAnimationTime;
    private boolean leftSide;
    private Paint paint = new Paint(1);
    private Path path1 = new Path();

    public interface VideoForwardDrawableDelegate {
        void invalidate();

        void onAnimationEnd();
    }

    public VideoForwardDrawable() {
        this.paint.setColor(-1);
        this.path1.reset();
        int a = 0;
        while (true) {
            if (a < playPath.length / 2) {
                if (a == 0) {
                    this.path1.moveTo(AndroidUtilities.dp(r2[a * 2]), AndroidUtilities.dp(playPath[(a * 2) + 1]));
                } else {
                    this.path1.lineTo(AndroidUtilities.dp(r2[a * 2]), AndroidUtilities.dp(playPath[(a * 2) + 1]));
                }
                a++;
            } else {
                this.path1.close();
                return;
            }
        }
    }

    public boolean isAnimating() {
        return this.animating;
    }

    public void startAnimation() {
        this.animating = true;
        this.animationProgress = 0.0f;
        invalidateSelf();
    }

    public void setLeftSide(boolean value) {
        if (this.leftSide == value && this.animationProgress >= 1.0f) {
            return;
        }
        this.leftSide = value;
        startAnimation();
    }

    public void setDelegate(VideoForwardDrawableDelegate videoForwardDrawableDelegate) {
        this.delegate = videoForwardDrawableDelegate;
    }

    @Override // android.graphics.drawable.Drawable
    public void setAlpha(int alpha) {
        this.paint.setAlpha(alpha);
    }

    @Override // android.graphics.drawable.Drawable
    public void setColorFilter(ColorFilter colorFilter) {
        this.paint.setColorFilter(colorFilter);
    }

    public void setColor(int value) {
        this.paint.setColor(value);
    }

    @Override // android.graphics.drawable.Drawable
    public int getOpacity() {
        return -2;
    }

    @Override // android.graphics.drawable.Drawable
    public void draw(Canvas canvas) {
        int x;
        android.graphics.Rect rect = getBounds();
        int x2 = rect.left + ((rect.width() - getIntrinsicWidth()) / 2);
        int y = rect.top + ((rect.height() - getIntrinsicHeight()) / 2);
        if (this.leftSide) {
            x = x2 - ((rect.width() / 4) - AndroidUtilities.dp(16.0f));
        } else {
            x = x2 + (rect.width() / 4) + AndroidUtilities.dp(16.0f);
        }
        canvas.save();
        canvas.clipRect(rect.left, rect.top, rect.right, rect.bottom);
        float f = this.animationProgress;
        if (f <= 0.7f) {
            this.paint.setAlpha((int) (Math.min(1.0f, f / 0.3f) * 80.0f));
        } else {
            this.paint.setAlpha((int) ((1.0f - ((f - 0.7f) / 0.3f)) * 80.0f));
        }
        canvas.drawCircle(((Math.max(rect.width(), rect.height()) / 4) * (this.leftSide ? -1 : 1)) + x, AndroidUtilities.dp(16.0f) + y, Math.max(rect.width(), rect.height()) / 2, this.paint);
        canvas.restore();
        canvas.save();
        if (this.leftSide) {
            canvas.rotate(180.0f, x, (getIntrinsicHeight() / 2) + y);
        }
        canvas.translate(x, y);
        float f2 = this.animationProgress;
        if (f2 <= 0.6f) {
            if (f2 < 0.4f) {
                this.paint.setAlpha(Math.min(255, (int) ((f2 * 255.0f) / 0.2f)));
            } else {
                this.paint.setAlpha((int) ((1.0f - ((f2 - 0.4f) / 0.2f)) * 255.0f));
            }
            canvas.drawPath(this.path1, this.paint);
        }
        canvas.translate(AndroidUtilities.dp(18.0f), 0.0f);
        float f3 = this.animationProgress;
        if (f3 >= 0.2f && f3 <= 0.8f) {
            float progress = f3 - 0.2f;
            if (progress < 0.4f) {
                this.paint.setAlpha(Math.min(255, (int) ((progress * 255.0f) / 0.2f)));
            } else {
                this.paint.setAlpha((int) ((1.0f - ((progress - 0.4f) / 0.2f)) * 255.0f));
            }
            canvas.drawPath(this.path1, this.paint);
        }
        canvas.translate(AndroidUtilities.dp(18.0f), 0.0f);
        float f4 = this.animationProgress;
        if (f4 >= 0.4f && f4 <= 1.0f) {
            float progress2 = f4 - 0.4f;
            if (progress2 < 0.4f) {
                this.paint.setAlpha(Math.min(255, (int) ((255.0f * progress2) / 0.2f)));
            } else {
                this.paint.setAlpha((int) ((1.0f - ((progress2 - 0.4f) / 0.2f)) * 255.0f));
            }
            canvas.drawPath(this.path1, this.paint);
        }
        canvas.restore();
        if (this.animating) {
            long newTime = System.currentTimeMillis();
            long dt = newTime - this.lastAnimationTime;
            if (dt > 17) {
                dt = 17;
            }
            this.lastAnimationTime = newTime;
            float f5 = this.animationProgress;
            if (f5 < 1.0f) {
                float f6 = f5 + (dt / 800.0f);
                this.animationProgress = f6;
                if (f6 >= 1.0f) {
                    this.animationProgress = 0.0f;
                    this.animating = false;
                    VideoForwardDrawableDelegate videoForwardDrawableDelegate = this.delegate;
                    if (videoForwardDrawableDelegate != null) {
                        videoForwardDrawableDelegate.onAnimationEnd();
                    }
                }
                VideoForwardDrawableDelegate videoForwardDrawableDelegate2 = this.delegate;
                if (videoForwardDrawableDelegate2 != null) {
                    videoForwardDrawableDelegate2.invalidate();
                } else {
                    invalidateSelf();
                }
            }
        }
    }

    @Override // android.graphics.drawable.Drawable
    public int getIntrinsicWidth() {
        return AndroidUtilities.dp(32.0f);
    }

    @Override // android.graphics.drawable.Drawable
    public int getIntrinsicHeight() {
        return AndroidUtilities.dp(32.0f);
    }

    @Override // android.graphics.drawable.Drawable
    public int getMinimumWidth() {
        return AndroidUtilities.dp(32.0f);
    }

    @Override // android.graphics.drawable.Drawable
    public int getMinimumHeight() {
        return AndroidUtilities.dp(32.0f);
    }
}
