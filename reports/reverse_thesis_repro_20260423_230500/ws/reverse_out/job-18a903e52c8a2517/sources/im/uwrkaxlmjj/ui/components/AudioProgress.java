package im.uwrkaxlmjj.ui.components;

import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.RectF;
import android.view.View;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ImageLocation;
import im.uwrkaxlmjj.messenger.ImageReceiver;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import java.util.Locale;

/* JADX INFO: loaded from: classes5.dex */
public class AudioProgress {
    private int backgroundStroke;
    private int circleColor;
    private String circleColorKey;
    private int circlePressedColor;
    private String circlePressedColorKey;
    private int circleRadius;
    private boolean drawMiniIcon;
    private int iconColor;
    private String iconColorKey;
    private int iconPressedColor;
    private String iconPressedColorKey;
    private boolean isPressed;
    private boolean isPressedMini;
    private MediaActionDrawable mediaActionDrawable;
    private Bitmap miniDrawBitmap;
    private Canvas miniDrawCanvas;
    private MediaActionDrawable miniMediaActionDrawable;
    private ImageReceiver overlayImageView;
    private View parent;
    private boolean previousCheckDrawable;
    private RectF progressRect = new RectF();
    private int progressColor = -1;
    private Paint overlayPaint = new Paint(1);
    private Paint circlePaint = new Paint(1);
    private Paint circleMiniPaint = new Paint(1);
    private boolean drawBackground = true;
    private float overrideAlpha = 1.0f;
    private Paint miniProgressBackgroundPaint = new Paint(1);

    public AudioProgress(View parentView) {
        this.parent = parentView;
        ImageReceiver imageReceiver = new ImageReceiver(parentView);
        this.overlayImageView = imageReceiver;
        imageReceiver.setInvalidateAll(true);
        MediaActionDrawable mediaActionDrawable = new MediaActionDrawable();
        this.mediaActionDrawable = mediaActionDrawable;
        parentView.getClass();
        mediaActionDrawable.setDelegate(new $$Lambda$YGZPgV16YyIwWk0pbwqhIcisSy4(parentView));
        MediaActionDrawable mediaActionDrawable2 = new MediaActionDrawable();
        this.miniMediaActionDrawable = mediaActionDrawable2;
        parentView.getClass();
        mediaActionDrawable2.setDelegate(new $$Lambda$YGZPgV16YyIwWk0pbwqhIcisSy4(parentView));
        this.miniMediaActionDrawable.setMini(true);
        this.miniMediaActionDrawable.setIcon(4, false);
        int iDp = AndroidUtilities.dp(22.0f);
        this.circleRadius = iDp;
        this.overlayImageView.setRoundRadius(iDp);
        this.overlayPaint.setColor(1677721600);
    }

    public void setCircleRadius(int value) {
        this.circleRadius = value;
        this.overlayImageView.setRoundRadius(value);
    }

    public void setBackgroundRadius(int value) {
        this.overlayImageView.setRoundRadius(value);
    }

    public void setBackgroundStroke(int value) {
        this.backgroundStroke = value;
        this.circlePaint.setStrokeWidth(value);
        this.circlePaint.setStyle(Paint.Style.STROKE);
        invalidateParent();
    }

    public void setImageOverlay(TLRPC.PhotoSize image, TLRPC.Document document, Object parentObject) {
        this.overlayImageView.setImage(ImageLocation.getForDocument(image, document), String.format(Locale.US, "%d_%d", Integer.valueOf(this.circleRadius * 2), Integer.valueOf(this.circleRadius * 2)), null, null, parentObject, 1);
    }

    public void setImageOverlay(String url) {
        this.overlayImageView.setImage(url, url != null ? String.format(Locale.US, "%d_%d", Integer.valueOf(this.circleRadius * 2), Integer.valueOf(this.circleRadius * 2)) : null, null, null, -1);
    }

    public void onAttachedToWindow() {
        this.overlayImageView.onAttachedToWindow();
    }

    public void onDetachedFromWindow() {
        this.overlayImageView.onDetachedFromWindow();
    }

    public void setColors(int circle, int circlePressed, int icon, int iconPressed) {
        this.circleColor = circle;
        this.circlePressedColor = circlePressed;
        this.iconColor = icon;
        this.iconPressedColor = iconPressed;
        this.circleColorKey = null;
        this.circlePressedColorKey = null;
        this.iconColorKey = null;
        this.iconPressedColorKey = null;
    }

    public void setColors(String circle, String circlePressed, String icon, String iconPressed) {
        this.circleColorKey = circle;
        this.circlePressedColorKey = circlePressed;
        this.iconColorKey = icon;
        this.iconPressedColorKey = iconPressed;
    }

    public void setDrawBackground(boolean value) {
        this.drawBackground = value;
    }

    public void setProgressRect(int left, int top, int right, int bottom) {
        this.progressRect.set(left, top, right, bottom);
    }

    public RectF getProgressRect() {
        return this.progressRect;
    }

    public void setProgressColor(int color) {
        this.progressColor = color;
    }

    public void setMiniProgressBackgroundColor(int color) {
        this.miniProgressBackgroundPaint.setColor(color);
    }

    public void setProgress(float value, boolean animated) {
        if (this.drawMiniIcon) {
            this.miniMediaActionDrawable.setProgress(value, animated);
        } else {
            this.mediaActionDrawable.setProgress(value, animated);
        }
    }

    private void invalidateParent() {
        int offset = AndroidUtilities.dp(2.0f);
        this.parent.invalidate(((int) this.progressRect.left) - offset, ((int) this.progressRect.top) - offset, ((int) this.progressRect.right) + (offset * 2), ((int) this.progressRect.bottom) + (offset * 2));
    }

    public int getIcon() {
        return this.mediaActionDrawable.getCurrentIcon();
    }

    public int getMiniIcon() {
        return this.miniMediaActionDrawable.getCurrentIcon();
    }

    public void setIcon(int icon, boolean ifSame, boolean animated) {
        if (ifSame && icon == this.mediaActionDrawable.getCurrentIcon()) {
            return;
        }
        this.mediaActionDrawable.setIcon(icon, animated);
        if (!animated) {
            this.parent.invalidate();
        } else {
            invalidateParent();
        }
    }

    public void setMiniIcon(int icon, boolean ifSame, boolean animated) {
        if (icon != 2 && icon != 3 && icon != 4) {
            return;
        }
        if (ifSame && icon == this.miniMediaActionDrawable.getCurrentIcon()) {
            return;
        }
        this.miniMediaActionDrawable.setIcon(icon, animated);
        boolean z = icon != 4 || this.miniMediaActionDrawable.getTransitionProgress() < 1.0f;
        this.drawMiniIcon = z;
        if (z) {
            initMiniIcons();
        }
        if (!animated) {
            this.parent.invalidate();
        } else {
            invalidateParent();
        }
    }

    public void initMiniIcons() {
        if (this.miniDrawBitmap == null) {
            try {
                this.miniDrawBitmap = Bitmap.createBitmap(AndroidUtilities.dp(48.0f), AndroidUtilities.dp(48.0f), Bitmap.Config.ARGB_8888);
                this.miniDrawCanvas = new Canvas(this.miniDrawBitmap);
            } catch (Throwable th) {
            }
        }
    }

    public boolean swapIcon(int icon) {
        return this.mediaActionDrawable.setIcon(icon, false);
    }

    public void setPressed(boolean value, boolean mini) {
        if (mini) {
            this.isPressedMini = value;
        } else {
            this.isPressed = value;
        }
        invalidateParent();
    }

    public void setOverrideAlpha(float alpha) {
        this.overrideAlpha = alpha;
    }

    public void draw(Canvas canvas) {
        float wholeAlpha;
        int color;
        int centerX;
        int centerY;
        int offset;
        int size;
        float cx;
        float cy;
        Canvas canvas2;
        Canvas canvas3;
        int r;
        if (this.mediaActionDrawable.getCurrentIcon() == 4 && this.mediaActionDrawable.getTransitionProgress() >= 1.0f) {
            return;
        }
        int currentIcon = this.mediaActionDrawable.getCurrentIcon();
        int prevIcon = this.mediaActionDrawable.getPreviousIcon();
        if (this.backgroundStroke != 0) {
            if (currentIcon == 3) {
                wholeAlpha = 1.0f - this.mediaActionDrawable.getTransitionProgress();
            } else if (prevIcon == 3) {
                wholeAlpha = this.mediaActionDrawable.getTransitionProgress();
            } else {
                wholeAlpha = 1.0f;
            }
        } else if ((currentIcon == 3 || currentIcon == 6 || currentIcon == 10 || currentIcon == 8 || currentIcon == 0) && prevIcon == 4) {
            wholeAlpha = this.mediaActionDrawable.getTransitionProgress();
        } else {
            wholeAlpha = currentIcon != 4 ? 1.0f : 1.0f - this.mediaActionDrawable.getTransitionProgress();
        }
        if (this.isPressedMini) {
            String str = this.iconPressedColorKey;
            if (str == null) {
                this.miniMediaActionDrawable.setColor(this.iconPressedColor);
            } else {
                this.miniMediaActionDrawable.setColor(Theme.getColor(str));
            }
            String str2 = this.circlePressedColorKey;
            if (str2 == null) {
                this.circleMiniPaint.setColor(this.circlePressedColor);
            } else {
                this.circleMiniPaint.setColor(Theme.getColor(str2));
            }
        } else {
            String str3 = this.iconColorKey;
            if (str3 == null) {
                this.miniMediaActionDrawable.setColor(this.iconColor);
            } else {
                this.miniMediaActionDrawable.setColor(Theme.getColor(str3));
            }
            String str4 = this.circleColorKey;
            if (str4 == null) {
                this.circleMiniPaint.setColor(this.circleColor);
            } else {
                this.circleMiniPaint.setColor(Theme.getColor(str4));
            }
        }
        if (this.isPressed) {
            String str5 = this.iconPressedColorKey;
            if (str5 != null) {
                MediaActionDrawable mediaActionDrawable = this.mediaActionDrawable;
                int color2 = Theme.getColor(str5);
                color = color2;
                mediaActionDrawable.setColor(color2);
            } else {
                MediaActionDrawable mediaActionDrawable2 = this.mediaActionDrawable;
                int i = this.iconPressedColor;
                color = i;
                mediaActionDrawable2.setColor(i);
            }
            String str6 = this.circlePressedColorKey;
            if (str6 == null) {
                this.circlePaint.setColor(this.circlePressedColor);
            } else {
                this.circlePaint.setColor(Theme.getColor(str6));
            }
        } else {
            String str7 = this.iconColorKey;
            if (str7 != null) {
                MediaActionDrawable mediaActionDrawable3 = this.mediaActionDrawable;
                int color3 = Theme.getColor(str7);
                color = color3;
                mediaActionDrawable3.setColor(color3);
            } else {
                MediaActionDrawable mediaActionDrawable4 = this.mediaActionDrawable;
                int i2 = this.iconColor;
                color = i2;
                mediaActionDrawable4.setColor(i2);
            }
            String str8 = this.circleColorKey;
            if (str8 == null) {
                this.circlePaint.setColor(this.circleColor);
            } else {
                this.circlePaint.setColor(Theme.getColor(str8));
            }
        }
        if (this.drawMiniIcon && this.miniDrawCanvas != null) {
            this.miniDrawBitmap.eraseColor(0);
        }
        int originalAlpha = this.circlePaint.getAlpha();
        this.circlePaint.setAlpha((int) (originalAlpha * wholeAlpha * this.overrideAlpha));
        int originalAlpha2 = this.circleMiniPaint.getAlpha();
        this.circleMiniPaint.setAlpha((int) (originalAlpha2 * wholeAlpha * this.overrideAlpha));
        boolean drawCircle = true;
        if (this.drawMiniIcon && this.miniDrawCanvas != null) {
            centerX = (int) (this.progressRect.width() / 2.0f);
            centerY = (int) (this.progressRect.height() / 2.0f);
        } else {
            centerX = (int) this.progressRect.centerX();
            centerY = (int) this.progressRect.centerY();
        }
        if (this.overlayImageView.hasBitmapImage()) {
            float alpha = this.overlayImageView.getCurrentAlpha();
            this.overlayPaint.setAlpha((int) (100.0f * alpha * wholeAlpha * this.overrideAlpha));
            if (alpha >= 1.0f) {
                drawCircle = false;
                r = -1;
            } else {
                int r2 = Color.red(color);
                int g = Color.green(color);
                int b = Color.blue(color);
                int a = Color.alpha(color);
                int rD = (int) ((255 - r2) * alpha);
                int originalAlpha3 = 255 - g;
                int gD = (int) (originalAlpha3 * alpha);
                int color4 = 255 - b;
                int bD = (int) (color4 * alpha);
                int aD = (int) ((255 - a) * alpha);
                int i3 = a + aD;
                int a2 = r2 + rD;
                int rD2 = g + gD;
                int gD2 = b + bD;
                r = Color.argb(i3, a2, rD2, gD2);
                drawCircle = true;
            }
            this.mediaActionDrawable.setColor(r);
            ImageReceiver imageReceiver = this.overlayImageView;
            int i4 = this.circleRadius;
            imageReceiver.setImageCoords(centerX - i4, centerY - i4, i4 * 2, i4 * 2);
        }
        if (drawCircle && this.drawBackground) {
            if (this.drawMiniIcon && (canvas3 = this.miniDrawCanvas) != null) {
                canvas3.drawCircle(centerX, centerY, this.circleRadius, this.circlePaint);
            } else if (currentIcon != 4 || wholeAlpha != 0.0f) {
                if (this.backgroundStroke != 0) {
                    canvas.drawCircle(centerX, centerY, this.circleRadius - AndroidUtilities.dp(3.5f), this.circlePaint);
                } else if (currentIcon == 1 || currentIcon == 0 || prevIcon == 1 || prevIcon == 0) {
                    canvas.drawCircle(centerX, centerY, this.circleRadius * wholeAlpha, this.circlePaint);
                } else {
                    int i5 = this.circleRadius;
                    float left = centerX - i5;
                    float right = centerX + i5;
                    float top = centerY - i5;
                    float bottom = i5 + centerY;
                    RectF rectF = new RectF(left, top, right, bottom);
                    canvas.drawRoundRect(rectF, AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), this.circleMiniPaint);
                }
            }
        }
        if (this.overlayImageView.hasBitmapImage()) {
            this.overlayImageView.setAlpha(this.overrideAlpha * wholeAlpha);
            if (this.drawMiniIcon && (canvas2 = this.miniDrawCanvas) != null) {
                this.overlayImageView.draw(canvas2);
                this.miniDrawCanvas.drawCircle(centerX, centerY, this.circleRadius, this.overlayPaint);
            } else {
                this.overlayImageView.draw(canvas);
                canvas.drawCircle(centerX, centerY, this.circleRadius, this.overlayPaint);
            }
        }
        MediaActionDrawable mediaActionDrawable5 = this.mediaActionDrawable;
        int i6 = this.circleRadius;
        mediaActionDrawable5.setBounds(centerX - i6, centerY - i6, centerX + i6, i6 + centerY);
        if (!this.drawMiniIcon) {
            this.mediaActionDrawable.setOverrideAlpha(this.overrideAlpha);
            this.mediaActionDrawable.draw(canvas);
        } else {
            Canvas canvas4 = this.miniDrawCanvas;
            if (canvas4 != null) {
                this.mediaActionDrawable.draw(canvas4);
            } else {
                this.mediaActionDrawable.draw(canvas);
            }
        }
        if (this.drawMiniIcon) {
            if (Math.abs(this.progressRect.width() - AndroidUtilities.dp(44.0f)) < AndroidUtilities.density) {
                offset = 0;
                size = 20;
                cx = this.progressRect.centerX() + AndroidUtilities.dp(0 + 16);
                cy = this.progressRect.centerY() + AndroidUtilities.dp(0 + 16);
            } else {
                offset = 2;
                size = 22;
                cx = this.progressRect.centerX() + AndroidUtilities.dp(18.0f);
                cy = AndroidUtilities.dp(18.0f) + this.progressRect.centerY();
            }
            int halfSize = size / 2;
            float alpha2 = this.miniMediaActionDrawable.getCurrentIcon() != 4 ? 1.0f : 1.0f - this.miniMediaActionDrawable.getTransitionProgress();
            if (alpha2 == 0.0f) {
                this.drawMiniIcon = false;
            }
            Canvas canvas5 = this.miniDrawCanvas;
            if (canvas5 == null) {
                this.miniProgressBackgroundPaint.setColor(this.progressColor);
                canvas.drawCircle(cx, cy, AndroidUtilities.dp(12.0f), this.miniProgressBackgroundPaint);
            } else {
                float fDp = AndroidUtilities.dp(size + 18 + offset);
                float fDp2 = AndroidUtilities.dp(size + 18 + offset);
                int offset2 = halfSize + 1;
                canvas5.drawCircle(fDp, fDp2, AndroidUtilities.dp(offset2) * alpha2, Theme.checkboxSquare_eraserPaint);
            }
            if (this.miniDrawCanvas != null) {
                canvas.drawBitmap(this.miniDrawBitmap, (int) this.progressRect.left, (int) this.progressRect.top, (Paint) null);
            }
            canvas.drawCircle(cx, cy, AndroidUtilities.dp(halfSize) * alpha2, this.circleMiniPaint);
            this.miniMediaActionDrawable.setBounds((int) (cx - (AndroidUtilities.dp(halfSize) * alpha2)), (int) (cy - (AndroidUtilities.dp(halfSize) * alpha2)), (int) ((AndroidUtilities.dp(halfSize) * alpha2) + cx), (int) ((AndroidUtilities.dp(halfSize) * alpha2) + cy));
            this.miniMediaActionDrawable.draw(canvas);
        }
    }
}
