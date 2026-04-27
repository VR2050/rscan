package im.uwrkaxlmjj.ui.components;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.ObjectAnimator;
import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Typeface;
import android.text.Layout;
import android.text.StaticLayout;
import android.text.TextPaint;
import android.view.View;
import androidx.core.app.NotificationCompat;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import java.util.ArrayList;
import java.util.Locale;

/* JADX INFO: loaded from: classes5.dex */
public class NumberTextView extends View {
    private ObjectAnimator animator;
    private int currentNumber;
    private ArrayList<StaticLayout> letters;
    private ArrayList<StaticLayout> oldLetters;
    private float progress;
    private TextPaint textPaint;

    public NumberTextView(Context context) {
        super(context);
        this.letters = new ArrayList<>();
        this.oldLetters = new ArrayList<>();
        this.textPaint = new TextPaint(1);
        this.progress = 0.0f;
        this.currentNumber = 1;
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

    public void setNumber(int number, boolean animated) {
        if (this.currentNumber == number && animated) {
            return;
        }
        ObjectAnimator objectAnimator = this.animator;
        if (objectAnimator != null) {
            objectAnimator.cancel();
            this.animator = null;
        }
        this.oldLetters.clear();
        this.oldLetters.addAll(this.letters);
        this.letters.clear();
        String oldText = String.format(Locale.US, "%d", Integer.valueOf(this.currentNumber));
        String text = String.format(Locale.US, "%d", Integer.valueOf(number));
        boolean forwardAnimation = number > this.currentNumber;
        this.currentNumber = number;
        this.progress = 0.0f;
        int a = 0;
        while (a < text.length()) {
            String ch = text.substring(a, a + 1);
            String oldCh = (this.oldLetters.isEmpty() || a >= oldText.length()) ? null : oldText.substring(a, a + 1);
            if (oldCh == null || !oldCh.equals(ch)) {
                StaticLayout layout = new StaticLayout(ch, this.textPaint, (int) Math.ceil(r13.measureText(ch)), Layout.Alignment.ALIGN_NORMAL, 1.0f, 0.0f, false);
                this.letters.add(layout);
            } else {
                this.letters.add(this.oldLetters.get(a));
                this.oldLetters.set(a, null);
            }
            a++;
        }
        if (animated && !this.oldLetters.isEmpty()) {
            float[] fArr = new float[2];
            fArr[0] = forwardAnimation ? -1.0f : 1.0f;
            fArr[1] = 0.0f;
            ObjectAnimator objectAnimatorOfFloat = ObjectAnimator.ofFloat(this, NotificationCompat.CATEGORY_PROGRESS, fArr);
            this.animator = objectAnimatorOfFloat;
            objectAnimatorOfFloat.setDuration(150L);
            this.animator.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.components.NumberTextView.1
                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationEnd(Animator animation) {
                    NumberTextView.this.animator = null;
                    NumberTextView.this.oldLetters.clear();
                }
            });
            this.animator.start();
        }
        invalidate();
    }

    public void setTextSize(int size) {
        this.textPaint.setTextSize(AndroidUtilities.dp(size));
        this.oldLetters.clear();
        this.letters.clear();
        setNumber(this.currentNumber, false);
    }

    public void setTextColor(int value) {
        this.textPaint.setColor(value);
        invalidate();
    }

    public void setTypeface(Typeface typeface) {
        this.textPaint.setTypeface(typeface);
        this.oldLetters.clear();
        this.letters.clear();
        setNumber(this.currentNumber, false);
    }

    @Override // android.view.View
    protected void onDraw(Canvas canvas) {
        if (this.letters.isEmpty()) {
            return;
        }
        float height = this.letters.get(0).getHeight();
        canvas.save();
        canvas.translate(getPaddingLeft(), (getMeasuredHeight() - height) / 2.0f);
        int count = Math.max(this.letters.size(), this.oldLetters.size());
        int a = 0;
        while (a < count) {
            canvas.save();
            StaticLayout old = a < this.oldLetters.size() ? this.oldLetters.get(a) : null;
            StaticLayout layout = a < this.letters.size() ? this.letters.get(a) : null;
            float f = this.progress;
            if (f > 0.0f) {
                if (old != null) {
                    this.textPaint.setAlpha((int) (f * 255.0f));
                    canvas.save();
                    canvas.translate(0.0f, (this.progress - 1.0f) * height);
                    old.draw(canvas);
                    canvas.restore();
                    if (layout != null) {
                        this.textPaint.setAlpha((int) ((1.0f - this.progress) * 255.0f));
                        canvas.translate(0.0f, this.progress * height);
                    }
                } else {
                    this.textPaint.setAlpha(255);
                }
            } else if (f < 0.0f) {
                if (old != null) {
                    this.textPaint.setAlpha((int) ((-f) * 255.0f));
                    canvas.save();
                    canvas.translate(0.0f, (this.progress + 1.0f) * height);
                    old.draw(canvas);
                    canvas.restore();
                }
                if (layout != null) {
                    if (a == count - 1 || old != null) {
                        this.textPaint.setAlpha((int) ((this.progress + 1.0f) * 255.0f));
                        canvas.translate(0.0f, this.progress * height);
                    } else {
                        this.textPaint.setAlpha(255);
                    }
                }
            } else if (layout != null) {
                this.textPaint.setAlpha(255);
            }
            if (layout != null) {
                layout.draw(canvas);
            }
            canvas.restore();
            canvas.translate(layout != null ? layout.getLineWidth(0) : old.getLineWidth(0) + AndroidUtilities.dp(1.0f), 0.0f);
            a++;
        }
        canvas.restore();
    }
}
