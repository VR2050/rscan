package im.uwrkaxlmjj.ui.components;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.RectF;
import im.uwrkaxlmjj.messenger.AndroidUtilities;

/* JADX INFO: loaded from: classes5.dex */
public class SeekBar {
    private static Paint paint;
    private static int thumbWidth;
    private int backgroundColor;
    private int backgroundSelectedColor;
    private float bufferedProgress;
    private int cacheColor;
    private int circleColor;
    private SeekBarDelegate delegate;
    private int height;
    private int progressColor;
    private boolean selected;
    private int width;
    private int thumbX = 0;
    private int draggingThumbX = 0;
    private int thumbDX = 0;
    private boolean pressed = false;
    private RectF rect = new RectF();
    private int lineHeight = AndroidUtilities.dp(2.0f);

    public interface SeekBarDelegate {
        void onSeekBarContinuousDrag(float f);

        void onSeekBarDrag(float f);

        /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.components.SeekBar$SeekBarDelegate$-CC, reason: invalid class name */
        public final /* synthetic */ class CC {
            public static void $default$onSeekBarContinuousDrag(SeekBarDelegate _this, float progress) {
            }
        }
    }

    public SeekBar(Context context) {
        if (paint == null) {
            paint = new Paint(1);
            thumbWidth = AndroidUtilities.dp(24.0f);
        }
    }

    public void setDelegate(SeekBarDelegate seekBarDelegate) {
        this.delegate = seekBarDelegate;
    }

    public boolean onTouch(int action, float x, float y) {
        SeekBarDelegate seekBarDelegate;
        if (action == 0) {
            int i = this.height;
            int additionWidth = (i - thumbWidth) / 2;
            int i2 = this.thumbX;
            if (i2 - additionWidth <= x && x <= r4 + i2 + additionWidth && y >= 0.0f && y <= i) {
                this.pressed = true;
                this.draggingThumbX = i2;
                this.thumbDX = (int) (x - i2);
                return true;
            }
        } else if (action == 1 || action == 3) {
            if (this.pressed) {
                int i3 = this.draggingThumbX;
                this.thumbX = i3;
                if (action == 1 && (seekBarDelegate = this.delegate) != null) {
                    seekBarDelegate.onSeekBarDrag(i3 / (this.width - thumbWidth));
                }
                this.pressed = false;
                return true;
            }
        } else if (action == 2 && this.pressed) {
            int i4 = (int) (x - this.thumbDX);
            this.draggingThumbX = i4;
            if (i4 < 0) {
                this.draggingThumbX = 0;
            } else {
                int i5 = this.width;
                int i6 = thumbWidth;
                if (i4 > i5 - i6) {
                    this.draggingThumbX = i5 - i6;
                }
            }
            SeekBarDelegate seekBarDelegate2 = this.delegate;
            if (seekBarDelegate2 != null) {
                seekBarDelegate2.onSeekBarContinuousDrag(this.draggingThumbX / (this.width - thumbWidth));
            }
            return true;
        }
        return false;
    }

    public boolean onTouchNew(int action, float x, float y) {
        SeekBarDelegate seekBarDelegate;
        SeekBarDelegate seekBarDelegate2;
        if (action == 0) {
            int i = this.height;
            int additionWidth = (i - thumbWidth) / 2;
            int i2 = this.thumbX;
            if (i2 - additionWidth <= x && x <= r5 + i2 + additionWidth && y >= 0.0f && y <= i) {
                this.pressed = true;
                this.draggingThumbX = i2;
                this.thumbDX = (int) (x - i2);
                return true;
            }
        } else if (action == 1 || action == 3) {
            if (this.pressed) {
                int i3 = this.draggingThumbX;
                this.thumbX = i3;
                if (action == 1 && (seekBarDelegate2 = this.delegate) != null) {
                    seekBarDelegate2.onSeekBarDrag(i3 / (this.width - thumbWidth));
                }
                this.pressed = false;
                return true;
            }
            if (x > 0.0f) {
                int i4 = this.width;
                if (x < i4 && action == 1 && (seekBarDelegate = this.delegate) != null) {
                    seekBarDelegate.onSeekBarDrag(x / i4);
                }
            }
        } else if (action == 2 && this.pressed) {
            int i5 = (int) (x - this.thumbDX);
            this.draggingThumbX = i5;
            if (i5 < 0) {
                this.draggingThumbX = 0;
            } else {
                int i6 = this.width;
                int i7 = thumbWidth;
                if (i5 > i6 - i7) {
                    this.draggingThumbX = i6 - i7;
                }
            }
            SeekBarDelegate seekBarDelegate3 = this.delegate;
            if (seekBarDelegate3 != null) {
                seekBarDelegate3.onSeekBarContinuousDrag(this.draggingThumbX / (this.width - thumbWidth));
            }
            return true;
        }
        return false;
    }

    public void setColors(int background, int cache, int progress, int circle, int selected) {
        this.backgroundColor = background;
        this.cacheColor = cache;
        this.circleColor = circle;
        this.progressColor = progress;
        this.backgroundSelectedColor = selected;
    }

    public void setProgress(float progress) {
        int iCeil = (int) Math.ceil((this.width - thumbWidth) * progress);
        this.thumbX = iCeil;
        if (iCeil < 0) {
            this.thumbX = 0;
            return;
        }
        int i = this.width;
        int i2 = thumbWidth;
        if (iCeil > i - i2) {
            this.thumbX = i - i2;
        }
    }

    public void setBufferedProgress(float value) {
        this.bufferedProgress = value;
    }

    public float getProgress() {
        return this.thumbX / (this.width - thumbWidth);
    }

    public int getThumbX() {
        return (this.pressed ? this.draggingThumbX : this.thumbX) + (thumbWidth / 2);
    }

    public boolean isDragging() {
        return this.pressed;
    }

    public void setSelected(boolean value) {
        this.selected = value;
    }

    public void setSize(int w, int h) {
        this.width = w;
        this.height = h;
    }

    public int getWidth() {
        return this.width - thumbWidth;
    }

    public void setLineHeight(int value) {
        this.lineHeight = value;
    }

    public void draw(Canvas canvas) {
        RectF rectF = this.rect;
        int i = thumbWidth;
        int i2 = this.height;
        int i3 = this.lineHeight;
        rectF.set(i / 2, (i2 / 2) - (i3 / 2), this.width - (i / 2), (i2 / 2) + (i3 / 2));
        paint.setColor(this.selected ? this.backgroundSelectedColor : this.backgroundColor);
        RectF rectF2 = this.rect;
        int i4 = thumbWidth;
        canvas.drawRoundRect(rectF2, i4 / 2, i4 / 2, paint);
        if (this.bufferedProgress > 0.0f) {
            paint.setColor(this.selected ? this.backgroundSelectedColor : this.cacheColor);
            RectF rectF3 = this.rect;
            int i5 = thumbWidth;
            int i6 = this.height;
            int i7 = this.lineHeight;
            rectF3.set(i5 / 2, (i6 / 2) - (i7 / 2), (i5 / 2) + (this.bufferedProgress * (this.width - i5)), (i6 / 2) + (i7 / 2));
            RectF rectF4 = this.rect;
            int i8 = thumbWidth;
            canvas.drawRoundRect(rectF4, i8 / 2, i8 / 2, paint);
        }
        RectF rectF5 = this.rect;
        int i9 = thumbWidth;
        int i10 = this.height;
        int i11 = this.lineHeight;
        rectF5.set(i9 / 2, (i10 / 2) - (i11 / 2), (i9 / 2) + this.thumbX, (i10 / 2) + (i11 / 2));
        paint.setColor(this.progressColor);
        RectF rectF6 = this.rect;
        int i12 = thumbWidth;
        canvas.drawRoundRect(rectF6, i12 / 2, i12 / 2, paint);
        paint.setColor(this.circleColor);
        canvas.drawCircle((this.pressed ? this.draggingThumbX : this.thumbX) + (thumbWidth / 2), this.height / 2, AndroidUtilities.dp(this.pressed ? 8.0f : 6.0f), paint);
    }
}
