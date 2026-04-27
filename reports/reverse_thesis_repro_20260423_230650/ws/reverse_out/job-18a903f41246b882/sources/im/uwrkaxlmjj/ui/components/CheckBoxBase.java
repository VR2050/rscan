package im.uwrkaxlmjj.ui.components;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.ObjectAnimator;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.PorterDuff;
import android.graphics.PorterDuffXfermode;
import android.graphics.RectF;
import android.text.TextPaint;
import android.view.View;
import androidx.core.app.NotificationCompat;
import androidx.core.view.ViewCompat;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.ui.actionbar.Theme;

/* JADX INFO: loaded from: classes5.dex */
public class CheckBoxBase {
    private static Paint eraser;
    private static Paint paint;
    private boolean attachedToWindow;
    private String background2ColorKey;
    private float backgroundAlpha;
    private String backgroundColorKey;
    private Paint backgroundPaint;
    private Canvas bitmapCanvas;
    private android.graphics.Rect bounds;
    private ObjectAnimator checkAnimator;
    private String checkColorKey;
    private Paint checkPaint;
    private String checkedText;
    private int drawBackgroundAsArc;
    private Bitmap drawBitmap;
    private boolean drawUnchecked;
    private boolean enabled;
    private boolean isChecked;
    private View parentView;
    private Path path;
    private float progress;
    private ProgressDelegate progressDelegate;
    private RectF rect;
    private float size;
    private TextPaint textPaint;
    private boolean useDefaultCheck;

    public interface ProgressDelegate {
        void setProgress(float f);
    }

    public CheckBoxBase(View parent) {
        this(parent, 21);
    }

    public CheckBoxBase(View parent, int sz) {
        this.bounds = new android.graphics.Rect();
        this.rect = new RectF();
        this.path = new Path();
        this.enabled = true;
        this.backgroundAlpha = 1.0f;
        this.checkColorKey = Theme.key_checkboxCheck;
        this.backgroundColorKey = Theme.key_divider;
        this.background2ColorKey = Theme.key_chat_serviceBackground;
        this.drawUnchecked = true;
        this.size = 21.0f;
        this.parentView = parent;
        this.size = sz;
        if (paint == null) {
            paint = new Paint(1);
            Paint paint2 = new Paint(1);
            eraser = paint2;
            paint2.setColor(Theme.getColor(Theme.key_switchTrackBlueChecked));
            eraser.setXfermode(new PorterDuffXfermode(PorterDuff.Mode.CLEAR));
        }
        Paint paint3 = new Paint(1);
        this.checkPaint = paint3;
        paint3.setStrokeCap(Paint.Cap.ROUND);
        this.checkPaint.setStyle(Paint.Style.STROKE);
        this.checkPaint.setStrokeJoin(Paint.Join.ROUND);
        this.checkPaint.setStrokeWidth(AndroidUtilities.dp(1.9f));
        Paint paint4 = new Paint(1);
        this.backgroundPaint = paint4;
        paint4.setStyle(Paint.Style.STROKE);
        this.backgroundPaint.setStrokeWidth(AndroidUtilities.dp(1.2f));
        this.drawBitmap = Bitmap.createBitmap(AndroidUtilities.dp(this.size), AndroidUtilities.dp(this.size), Bitmap.Config.ARGB_4444);
        this.bitmapCanvas = new Canvas(this.drawBitmap);
    }

    public void onAttachedToWindow() {
        this.attachedToWindow = true;
    }

    public void onDetachedFromWindow() {
        this.attachedToWindow = false;
    }

    public void setBounds(int x, int y, int width, int height) {
        this.bounds.left = x;
        this.bounds.top = y;
        this.bounds.right = x + width;
        this.bounds.bottom = y + height;
    }

    public void setDrawUnchecked(boolean value) {
        this.drawUnchecked = value;
    }

    public void setProgress(float value) {
        if (this.progress == value) {
            return;
        }
        this.progress = value;
        invalidate();
        ProgressDelegate progressDelegate = this.progressDelegate;
        if (progressDelegate != null) {
            progressDelegate.setProgress(value);
        }
    }

    private void invalidate() {
        if (this.parentView.getParent() != null) {
            View parent = (View) this.parentView.getParent();
            parent.invalidate();
        }
        View parent2 = this.parentView;
        parent2.invalidate();
    }

    public void setProgressDelegate(ProgressDelegate delegate) {
        this.progressDelegate = delegate;
    }

    public float getProgress() {
        return this.progress;
    }

    public boolean isChecked() {
        return this.isChecked;
    }

    public void setEnabled(boolean value) {
        this.enabled = value;
    }

    public void setDrawBackgroundAsArc(int type) {
        this.drawBackgroundAsArc = type;
        if (type == 4 || type == 5) {
            this.backgroundPaint.setStrokeWidth(AndroidUtilities.dp(1.9f));
            if (type == 5) {
                this.checkPaint.setStrokeWidth(AndroidUtilities.dp(1.5f));
                return;
            }
            return;
        }
        if (type == 3) {
            this.backgroundPaint.setStrokeWidth(AndroidUtilities.dp(1.2f));
        } else if (type != 0) {
            this.backgroundPaint.setStrokeWidth(AndroidUtilities.dp(1.5f));
        }
    }

    private void cancelCheckAnimator() {
        ObjectAnimator objectAnimator = this.checkAnimator;
        if (objectAnimator != null) {
            objectAnimator.cancel();
            this.checkAnimator = null;
        }
    }

    private void animateToCheckedState(boolean newCheckedState) {
        float[] fArr = new float[1];
        fArr[0] = newCheckedState ? 1.0f : 0.0f;
        ObjectAnimator objectAnimatorOfFloat = ObjectAnimator.ofFloat(this, NotificationCompat.CATEGORY_PROGRESS, fArr);
        this.checkAnimator = objectAnimatorOfFloat;
        objectAnimatorOfFloat.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.components.CheckBoxBase.1
            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationEnd(Animator animation) {
                if (animation.equals(CheckBoxBase.this.checkAnimator)) {
                    CheckBoxBase.this.checkAnimator = null;
                }
                if (!CheckBoxBase.this.isChecked) {
                    CheckBoxBase.this.checkedText = null;
                }
            }
        });
        this.checkAnimator.setInterpolator(CubicBezierInterpolator.EASE_OUT);
        this.checkAnimator.setDuration(200L);
        this.checkAnimator.start();
    }

    public void setColor(String background, String background2, String check) {
        this.backgroundColorKey = background;
        this.background2ColorKey = background2;
        this.checkColorKey = check;
    }

    public void setUseDefaultCheck(boolean value) {
        this.useDefaultCheck = value;
    }

    public void setBackgroundAlpha(float alpha) {
        this.backgroundAlpha = alpha;
    }

    public void setNum(int num) {
        if (num >= 0) {
            this.checkedText = "" + (num + 1);
        } else if (this.checkAnimator == null) {
            this.checkedText = null;
        }
        invalidate();
    }

    public void setChecked(boolean checked, boolean animated) {
        setChecked(-1, checked, animated);
    }

    public void setChecked(int num, boolean checked, boolean animated) {
        if (num >= 0) {
            this.checkedText = "" + (num + 1);
            invalidate();
        }
        if (checked == this.isChecked) {
            return;
        }
        this.isChecked = checked;
        if (this.attachedToWindow && animated) {
            animateToCheckedState(checked);
        } else {
            cancelCheckAnimator();
            setProgress(checked ? 1.0f : 0.0f);
        }
    }

    public void draw(Canvas canvas) {
        float outerRad;
        int i;
        String str;
        int startAngle;
        int sweepAngle;
        Bitmap bitmap = this.drawBitmap;
        if (bitmap == null) {
            return;
        }
        bitmap.eraseColor(0);
        float rad = AndroidUtilities.dp(this.size / 2.0f);
        if (this.drawBackgroundAsArc != 0) {
            float outerRad2 = rad - AndroidUtilities.dp(0.2f);
            outerRad = outerRad2;
        } else {
            outerRad = rad;
        }
        float outerRad3 = this.progress;
        float roundProgress = outerRad3 >= 0.5f ? 1.0f : outerRad3 / 0.5f;
        int cx = this.bounds.centerX();
        int cy = this.bounds.centerY();
        if (this.backgroundColorKey != null) {
            if (this.drawUnchecked) {
                paint.setColor(0);
                if (!this.isChecked) {
                    this.backgroundPaint.setColor(Theme.getColor(this.backgroundColorKey));
                } else {
                    this.backgroundPaint.setColor(0);
                }
            } else {
                Paint paint2 = this.backgroundPaint;
                String str2 = this.background2ColorKey;
                if (str2 == null) {
                    str2 = this.checkColorKey;
                }
                paint2.setColor(AndroidUtilities.getOffsetColor(ViewCompat.MEASURED_SIZE_MASK, Theme.getColor(str2), this.progress, this.backgroundAlpha));
            }
        } else if (this.drawUnchecked) {
            paint.setColor(Color.argb((int) (this.backgroundAlpha * 25.0f), 0, 0, 0));
            this.backgroundPaint.setColor(AndroidUtilities.getOffsetColor(-1, Theme.getColor(this.checkColorKey), this.progress, this.backgroundAlpha));
        } else {
            Paint paint3 = this.backgroundPaint;
            String str3 = this.background2ColorKey;
            if (str3 == null) {
                str3 = this.checkColorKey;
            }
            paint3.setColor(AndroidUtilities.getOffsetColor(ViewCompat.MEASURED_SIZE_MASK, Theme.getColor(str3), this.progress, this.backgroundAlpha));
        }
        if (this.drawUnchecked) {
            int i2 = this.drawBackgroundAsArc;
            if (i2 == 6 || i2 == 7) {
                canvas.drawCircle(cx, cy, rad - AndroidUtilities.dp(1.0f), paint);
                canvas.drawCircle(cx, cy, rad - AndroidUtilities.dp(1.5f), this.backgroundPaint);
            } else {
                canvas.drawCircle(cx, cy, rad, paint);
            }
        }
        paint.setColor(Theme.getColor(this.checkColorKey));
        int i3 = this.drawBackgroundAsArc;
        if (i3 == 7) {
            i = 7;
        } else if (i3 == 0) {
            canvas.drawCircle(cx, cy, rad, this.backgroundPaint);
            i = 7;
        } else {
            this.rect.set(cx - outerRad, cy - outerRad, cx + outerRad, cy + outerRad);
            int startAngle2 = this.drawBackgroundAsArc;
            if (startAngle2 == 6) {
                startAngle = 0;
                sweepAngle = (int) (this.progress * (-360.0f));
            } else if (startAngle2 == 1) {
                startAngle = -90;
                sweepAngle = (int) (this.progress * (-270.0f));
            } else {
                startAngle = 90;
                sweepAngle = (int) (this.progress * 270.0f);
            }
            if (this.drawBackgroundAsArc != 6) {
                i = 7;
                canvas.drawArc(this.rect, startAngle, sweepAngle, false, this.backgroundPaint);
            } else {
                int color = Theme.getColor(Theme.key_dialogBackground);
                int alpha = Color.alpha(color);
                this.backgroundPaint.setColor(color);
                this.backgroundPaint.setAlpha((int) (alpha * this.progress));
                int sweepAngle2 = sweepAngle;
                i = 7;
                canvas.drawArc(this.rect, startAngle, sweepAngle, false, this.backgroundPaint);
                int color2 = Theme.getColor(Theme.key_chat_attachPhotoBackground);
                int alpha2 = Color.alpha(color2);
                this.backgroundPaint.setColor(color2);
                this.backgroundPaint.setAlpha((int) (alpha2 * this.progress));
                canvas.drawArc(this.rect, startAngle, sweepAngle2, false, this.backgroundPaint);
            }
        }
        if (roundProgress > 0.0f) {
            float f = this.progress;
            float checkProgress = f < 0.5f ? 0.0f : (f - 0.5f) / 0.5f;
            int i4 = this.drawBackgroundAsArc;
            if (i4 == 6 || i4 == i || (!this.drawUnchecked && this.backgroundColorKey != null)) {
                paint.setColor(Theme.getColor(this.backgroundColorKey));
            } else {
                paint.setColor(Theme.getColor(this.enabled ? Theme.key_checkbox : Theme.key_checkboxDisabled));
            }
            if (!this.useDefaultCheck && (str = this.checkColorKey) != null) {
                this.checkPaint.setColor(Theme.getColor(str));
            } else {
                this.checkPaint.setColor(Theme.getColor(Theme.key_checkboxCheck));
            }
            float rad2 = rad - AndroidUtilities.dp(0.5f);
            this.bitmapCanvas.drawCircle(this.drawBitmap.getWidth() / 2, this.drawBitmap.getHeight() / 2, rad2, paint);
            this.bitmapCanvas.drawCircle(this.drawBitmap.getWidth() / 2, this.drawBitmap.getWidth() / 2, (1.0f - roundProgress) * rad2, eraser);
            canvas.drawBitmap(this.drawBitmap, cx - (r3.getWidth() / 2), cy - (this.drawBitmap.getHeight() / 2), (Paint) null);
            if (checkProgress != 0.0f) {
                if (this.checkedText == null) {
                    this.path.reset();
                    float scale = this.drawBackgroundAsArc == 5 ? 0.8f : 1.0f;
                    float checkSide = AndroidUtilities.dp(9.0f * scale) * checkProgress;
                    float smallCheckSide = AndroidUtilities.dp(scale * 4.0f) * checkProgress;
                    int x = cx - AndroidUtilities.dp(1.5f);
                    int y = AndroidUtilities.dp(4.0f) + cy;
                    float side = (float) Math.sqrt((smallCheckSide * smallCheckSide) / 2.0f);
                    this.path.moveTo(x - side, y - side);
                    this.path.lineTo(x, y);
                    float side2 = (float) Math.sqrt((checkSide * checkSide) / 2.0f);
                    this.path.lineTo(x + side2, y - side2);
                    canvas.drawPath(this.path, this.checkPaint);
                    return;
                }
                if (this.textPaint == null) {
                    TextPaint textPaint = new TextPaint(1);
                    this.textPaint = textPaint;
                    textPaint.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
                }
                int color3 = Theme.getColor(this.checkColorKey);
                Color.alpha(color3);
                this.textPaint.setColor(color3);
                this.textPaint.setTextSize(AndroidUtilities.dp(14.0f));
                int w = (int) Math.ceil(this.textPaint.measureText(this.checkedText));
                canvas.save();
                canvas.scale(checkProgress, 1.0f, cx, cy);
                canvas.drawText(this.checkedText, cx - (w / 2), AndroidUtilities.dp(18.0f), this.textPaint);
                canvas.restore();
            }
        }
    }
}
