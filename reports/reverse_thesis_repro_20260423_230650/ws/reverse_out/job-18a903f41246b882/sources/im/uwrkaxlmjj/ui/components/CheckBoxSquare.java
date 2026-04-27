package im.uwrkaxlmjj.ui.components;

import android.animation.ObjectAnimator;
import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.RectF;
import android.view.View;
import androidx.core.app.NotificationCompat;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.ui.actionbar.Theme;

/* JADX INFO: loaded from: classes5.dex */
public class CheckBoxSquare extends View {
    private static final float progressBounceDiff = 0.2f;
    private boolean attachedToWindow;
    private ObjectAnimator checkAnimator;
    private Bitmap drawBitmap;
    private Canvas drawCanvas;
    private boolean isAlert;
    private boolean isChecked;
    private boolean isDisabled;
    private float progress;
    private RectF rectF;

    public CheckBoxSquare(Context context, boolean alert) {
        super(context);
        if (Theme.checkboxSquare_backgroundPaint == null) {
            Theme.createCommonResources(context);
        }
        this.rectF = new RectF();
        this.drawBitmap = Bitmap.createBitmap(AndroidUtilities.dp(18.0f), AndroidUtilities.dp(18.0f), Bitmap.Config.ARGB_4444);
        this.drawCanvas = new Canvas(this.drawBitmap);
        this.isAlert = alert;
    }

    public void setProgress(float value) {
        if (this.progress == value) {
            return;
        }
        this.progress = value;
        invalidate();
    }

    public float getProgress() {
        return this.progress;
    }

    private void cancelCheckAnimator() {
        ObjectAnimator objectAnimator = this.checkAnimator;
        if (objectAnimator != null) {
            objectAnimator.cancel();
        }
    }

    private void animateToCheckedState(boolean newCheckedState) {
        float[] fArr = new float[1];
        fArr[0] = newCheckedState ? 1.0f : 0.0f;
        ObjectAnimator objectAnimatorOfFloat = ObjectAnimator.ofFloat(this, NotificationCompat.CATEGORY_PROGRESS, fArr);
        this.checkAnimator = objectAnimatorOfFloat;
        objectAnimatorOfFloat.setDuration(300L);
        this.checkAnimator.start();
    }

    @Override // android.view.View
    protected void onAttachedToWindow() {
        super.onAttachedToWindow();
        this.attachedToWindow = true;
    }

    @Override // android.view.View
    protected void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        this.attachedToWindow = false;
    }

    @Override // android.view.View
    protected void onLayout(boolean changed, int left, int top, int right, int bottom) {
        super.onLayout(changed, left, top, right, bottom);
    }

    public void setChecked(boolean checked, boolean animated) {
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

    public void setDisabled(boolean disabled) {
        this.isDisabled = disabled;
        invalidate();
    }

    public boolean isChecked() {
        return this.isChecked;
    }

    @Override // android.view.View
    protected void onDraw(Canvas canvas) {
        float bounceProgress;
        float checkProgress;
        if (getVisibility() != 0) {
            return;
        }
        int uncheckedColor = Theme.getColor(this.isAlert ? Theme.key_dialogCheckboxSquareUnchecked : Theme.key_checkboxSquareUnchecked);
        int color = Theme.getColor(this.isAlert ? Theme.key_dialogCheckboxSquareBackground : Theme.key_checkboxSquareBackground);
        float bounceProgress2 = this.progress;
        if (bounceProgress2 <= 0.5f) {
            bounceProgress = bounceProgress2 / 0.5f;
            checkProgress = bounceProgress;
            int rD = (int) ((Color.red(color) - Color.red(uncheckedColor)) * checkProgress);
            int gD = (int) ((Color.green(color) - Color.green(uncheckedColor)) * checkProgress);
            int bD = (int) ((Color.blue(color) - Color.blue(uncheckedColor)) * checkProgress);
            int c = Color.rgb(Color.red(uncheckedColor) + rD, Color.green(uncheckedColor) + gD, Color.blue(uncheckedColor) + bD);
            Theme.checkboxSquare_backgroundPaint.setColor(c);
        } else {
            bounceProgress = 2.0f - (bounceProgress2 / 0.5f);
            checkProgress = 1.0f;
            Theme.checkboxSquare_backgroundPaint.setColor(color);
        }
        if (this.isDisabled) {
            Theme.checkboxSquare_backgroundPaint.setColor(Theme.getColor(this.isAlert ? Theme.key_dialogCheckboxSquareDisabled : Theme.key_checkboxSquareDisabled));
        }
        float bounce = AndroidUtilities.dp(1.0f) * bounceProgress;
        this.rectF.set(bounce, bounce, AndroidUtilities.dp(18.0f) - bounce, AndroidUtilities.dp(18.0f) - bounce);
        this.drawBitmap.eraseColor(0);
        this.drawCanvas.drawRoundRect(this.rectF, AndroidUtilities.dp(2.0f), AndroidUtilities.dp(2.0f), Theme.checkboxSquare_backgroundPaint);
        if (checkProgress != 1.0f) {
            float rad = Math.min(AndroidUtilities.dp(7.0f), (AndroidUtilities.dp(7.0f) * checkProgress) + bounce);
            this.rectF.set(AndroidUtilities.dp(2.0f) + rad, AndroidUtilities.dp(2.0f) + rad, AndroidUtilities.dp(16.0f) - rad, AndroidUtilities.dp(16.0f) - rad);
            this.drawCanvas.drawRect(this.rectF, Theme.checkboxSquare_eraserPaint);
        }
        if (this.progress > 0.5f) {
            Theme.checkboxSquare_checkPaint.setColor(Theme.getColor(this.isAlert ? Theme.key_dialogCheckboxSquareCheck : Theme.key_checkboxSquareCheck));
            int endX = (int) (AndroidUtilities.dp(7.5f) - (AndroidUtilities.dp(5.0f) * (1.0f - bounceProgress)));
            int endY = (int) (AndroidUtilities.dpf2(13.5f) - (AndroidUtilities.dp(5.0f) * (1.0f - bounceProgress)));
            this.drawCanvas.drawLine(AndroidUtilities.dp(7.5f), (int) AndroidUtilities.dpf2(13.5f), endX, endY, Theme.checkboxSquare_checkPaint);
            int endX2 = (int) (AndroidUtilities.dpf2(6.5f) + (AndroidUtilities.dp(9.0f) * (1.0f - bounceProgress)));
            int endY2 = (int) (AndroidUtilities.dpf2(13.5f) - (AndroidUtilities.dp(9.0f) * (1.0f - bounceProgress)));
            this.drawCanvas.drawLine((int) AndroidUtilities.dpf2(6.5f), (int) AndroidUtilities.dpf2(13.5f), endX2, endY2, Theme.checkboxSquare_checkPaint);
        }
        canvas.drawBitmap(this.drawBitmap, 0.0f, 0.0f, (Paint) null);
    }
}
