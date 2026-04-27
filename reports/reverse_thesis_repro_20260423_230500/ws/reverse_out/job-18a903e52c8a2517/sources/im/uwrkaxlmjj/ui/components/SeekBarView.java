package im.uwrkaxlmjj.ui.components;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.view.MotionEvent;
import android.widget.FrameLayout;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.ui.actionbar.Theme;

/* JADX INFO: loaded from: classes5.dex */
public class SeekBarView extends FrameLayout {
    private float bufferedProgress;
    private SeekBarViewDelegate delegate;
    private Paint innerPaint1;
    private Paint outerPaint1;
    private boolean pressed;
    private float progressToSet;
    private boolean reportChanges;
    private int thumbDX;
    private int thumbHeight;
    private int thumbWidth;
    private int thumbX;

    public interface SeekBarViewDelegate {
        void onSeekBarDrag(float f);
    }

    public SeekBarView(Context context) {
        super(context);
        setWillNotDraw(false);
        Paint paint = new Paint(1);
        this.innerPaint1 = paint;
        paint.setColor(Theme.getColor(Theme.key_player_progressBackground));
        Paint paint2 = new Paint(1);
        this.outerPaint1 = paint2;
        paint2.setColor(Theme.getColor(Theme.key_player_progress));
        this.thumbWidth = AndroidUtilities.dp(24.0f);
        this.thumbHeight = AndroidUtilities.dp(24.0f);
    }

    public void setColors(int inner, int outer) {
        this.innerPaint1.setColor(inner);
        this.outerPaint1.setColor(outer);
    }

    public void setInnerColor(int inner) {
        this.innerPaint1.setColor(inner);
    }

    public void setOuterColor(int outer) {
        this.outerPaint1.setColor(outer);
    }

    @Override // android.view.ViewGroup
    public boolean onInterceptTouchEvent(MotionEvent ev) {
        return onTouch(ev);
    }

    @Override // android.view.View
    public boolean onTouchEvent(MotionEvent event) {
        return onTouch(event);
    }

    public void setReportChanges(boolean value) {
        this.reportChanges = value;
    }

    public void setDelegate(SeekBarViewDelegate seekBarViewDelegate) {
        this.delegate = seekBarViewDelegate;
    }

    boolean onTouch(MotionEvent ev) {
        if (ev.getAction() == 0) {
            getParent().requestDisallowInterceptTouchEvent(true);
            int additionWidth = (getMeasuredHeight() - this.thumbWidth) / 2;
            if (ev.getY() >= 0.0f && ev.getY() <= getMeasuredHeight()) {
                if (this.thumbX - additionWidth > ev.getX() || ev.getX() > this.thumbX + this.thumbWidth + additionWidth) {
                    int x = ((int) ev.getX()) - (this.thumbWidth / 2);
                    this.thumbX = x;
                    if (x < 0) {
                        this.thumbX = 0;
                    } else if (x > getMeasuredWidth() - this.thumbWidth) {
                        this.thumbX = getMeasuredWidth() - this.thumbWidth;
                    }
                }
                this.thumbDX = (int) (ev.getX() - this.thumbX);
                this.pressed = true;
                invalidate();
                return true;
            }
        } else if (ev.getAction() == 1 || ev.getAction() == 3) {
            if (this.pressed) {
                if (ev.getAction() == 1) {
                    this.delegate.onSeekBarDrag(this.thumbX / (getMeasuredWidth() - this.thumbWidth));
                }
                this.pressed = false;
                invalidate();
                return true;
            }
        } else if (ev.getAction() == 2 && this.pressed) {
            int x2 = (int) (ev.getX() - this.thumbDX);
            this.thumbX = x2;
            if (x2 < 0) {
                this.thumbX = 0;
            } else if (x2 > getMeasuredWidth() - this.thumbWidth) {
                this.thumbX = getMeasuredWidth() - this.thumbWidth;
            }
            if (this.reportChanges) {
                this.delegate.onSeekBarDrag(this.thumbX / (getMeasuredWidth() - this.thumbWidth));
            }
            invalidate();
            return true;
        }
        return false;
    }

    public void setProgress(float progress) {
        if (getMeasuredWidth() == 0) {
            this.progressToSet = progress;
            return;
        }
        this.progressToSet = -1.0f;
        int newThumbX = (int) Math.ceil((getMeasuredWidth() - this.thumbWidth) * progress);
        if (this.thumbX != newThumbX) {
            this.thumbX = newThumbX;
            if (newThumbX < 0) {
                this.thumbX = 0;
            } else if (newThumbX > getMeasuredWidth() - this.thumbWidth) {
                this.thumbX = getMeasuredWidth() - this.thumbWidth;
            }
            invalidate();
        }
    }

    public void setBufferedProgress(float progress) {
        this.bufferedProgress = progress;
    }

    @Override // android.widget.FrameLayout, android.view.View
    protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        super.onMeasure(widthMeasureSpec, heightMeasureSpec);
        if (this.progressToSet >= 0.0f && getMeasuredWidth() > 0) {
            setProgress(this.progressToSet);
            this.progressToSet = -1.0f;
        }
    }

    public boolean isDragging() {
        return this.pressed;
    }

    @Override // android.view.View
    protected void onDraw(Canvas canvas) {
        int y = (getMeasuredHeight() - this.thumbHeight) / 2;
        canvas.drawRect(this.thumbWidth / 2, (getMeasuredHeight() / 2) - AndroidUtilities.dp(1.0f), getMeasuredWidth() - (this.thumbWidth / 2), (getMeasuredHeight() / 2) + AndroidUtilities.dp(1.0f), this.innerPaint1);
        if (this.bufferedProgress > 0.0f) {
            canvas.drawRect(this.thumbWidth / 2, (getMeasuredHeight() / 2) - AndroidUtilities.dp(1.0f), (this.thumbWidth / 2) + (this.bufferedProgress * (getMeasuredWidth() - this.thumbWidth)), (getMeasuredHeight() / 2) + AndroidUtilities.dp(1.0f), this.innerPaint1);
        }
        canvas.drawRect(this.thumbWidth / 2, (getMeasuredHeight() / 2) - AndroidUtilities.dp(1.0f), (this.thumbWidth / 2) + this.thumbX, (getMeasuredHeight() / 2) + AndroidUtilities.dp(1.0f), this.outerPaint1);
        canvas.drawCircle(this.thumbX + (this.thumbWidth / 2), (this.thumbHeight / 2) + y, AndroidUtilities.dp(this.pressed ? 8.0f : 6.0f), this.outerPaint1);
    }
}
