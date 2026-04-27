package im.uwrkaxlmjj.ui.components;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.ColorFilter;
import android.graphics.Paint;
import android.graphics.drawable.Drawable;
import android.text.Layout;
import android.text.StaticLayout;
import android.text.TextPaint;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.ui.actionbar.Theme;

/* JADX INFO: loaded from: classes5.dex */
public class TimerDrawable extends Drawable {
    private StaticLayout timeLayout;
    private TextPaint timePaint = new TextPaint(1);
    private Paint paint = new Paint(1);
    private Paint linePaint = new Paint(1);
    private float timeWidth = 0.0f;
    private int timeHeight = 0;
    private int time = 0;

    public TimerDrawable(Context context) {
        this.timePaint.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
        this.timePaint.setTextSize(AndroidUtilities.dp(11.0f));
        this.linePaint.setStrokeWidth(AndroidUtilities.dp(1.0f));
        this.linePaint.setStyle(Paint.Style.STROKE);
    }

    public void setTime(int value) {
        String timeString;
        this.time = value;
        if (value >= 1 && value < 60) {
            timeString = "" + value;
            if (timeString.length() < 2) {
                timeString = timeString + "s";
            }
        } else {
            int i = this.time;
            if (i >= 60 && i < 3600) {
                timeString = "" + (value / 60);
                if (timeString.length() < 2) {
                    timeString = timeString + "m";
                }
            } else {
                int i2 = this.time;
                if (i2 >= 3600 && i2 < 86400) {
                    timeString = "" + ((value / 60) / 60);
                    if (timeString.length() < 2) {
                        timeString = timeString + "h";
                    }
                } else {
                    int i3 = this.time;
                    if (i3 >= 86400 && i3 < 604800) {
                        timeString = "" + (((value / 60) / 60) / 24);
                        if (timeString.length() < 2) {
                            timeString = timeString + "d";
                        }
                    } else {
                        timeString = "" + ((((value / 60) / 60) / 24) / 7);
                        if (timeString.length() < 2) {
                            timeString = timeString + "w";
                        } else if (timeString.length() > 2) {
                            timeString = "c";
                        }
                    }
                }
            }
        }
        this.timeWidth = this.timePaint.measureText(timeString);
        try {
            StaticLayout staticLayout = new StaticLayout(timeString, this.timePaint, (int) Math.ceil(this.timeWidth), Layout.Alignment.ALIGN_NORMAL, 1.0f, 0.0f, false);
            this.timeLayout = staticLayout;
            this.timeHeight = staticLayout.getHeight();
        } catch (Exception e) {
            this.timeLayout = null;
            FileLog.e(e);
        }
        invalidateSelf();
    }

    @Override // android.graphics.drawable.Drawable
    public void draw(Canvas canvas) {
        int width = getIntrinsicWidth();
        int height = getIntrinsicHeight();
        if (this.time == 0) {
            this.paint.setColor(Theme.getColor(Theme.key_chat_secretTimerBackground));
            this.linePaint.setColor(Theme.getColor(Theme.key_chat_secretTimerText));
            canvas.drawCircle(AndroidUtilities.dpf2(9.0f), AndroidUtilities.dpf2(9.0f), AndroidUtilities.dpf2(7.5f), this.paint);
            canvas.drawCircle(AndroidUtilities.dpf2(9.0f), AndroidUtilities.dpf2(9.0f), AndroidUtilities.dpf2(8.0f), this.linePaint);
            this.paint.setColor(Theme.getColor(Theme.key_chat_secretTimerText));
            canvas.drawLine(AndroidUtilities.dp(9.0f), AndroidUtilities.dp(9.0f), AndroidUtilities.dp(13.0f), AndroidUtilities.dp(9.0f), this.linePaint);
            canvas.drawLine(AndroidUtilities.dp(9.0f), AndroidUtilities.dp(5.0f), AndroidUtilities.dp(9.0f), AndroidUtilities.dp(9.5f), this.linePaint);
            canvas.drawRect(AndroidUtilities.dpf2(7.0f), AndroidUtilities.dpf2(0.0f), AndroidUtilities.dpf2(11.0f), AndroidUtilities.dpf2(1.5f), this.paint);
        } else {
            this.paint.setColor(Theme.getColor(Theme.key_chat_secretTimerBackground));
            this.timePaint.setColor(Theme.getColor(Theme.key_chat_secretTimerText));
            canvas.drawCircle(AndroidUtilities.dp(9.5f), AndroidUtilities.dp(9.5f), AndroidUtilities.dp(9.5f), this.paint);
        }
        if (this.time != 0 && this.timeLayout != null) {
            int xOffxet = 0;
            if (AndroidUtilities.density == 3.0f) {
                xOffxet = -1;
            }
            canvas.translate(((int) (((double) (width / 2)) - Math.ceil(this.timeWidth / 2.0f))) + xOffxet, (height - this.timeHeight) / 2);
            this.timeLayout.draw(canvas);
        }
    }

    @Override // android.graphics.drawable.Drawable
    public void setAlpha(int alpha) {
    }

    @Override // android.graphics.drawable.Drawable
    public void setColorFilter(ColorFilter cf) {
    }

    @Override // android.graphics.drawable.Drawable
    public int getOpacity() {
        return 0;
    }

    @Override // android.graphics.drawable.Drawable
    public int getIntrinsicWidth() {
        return AndroidUtilities.dp(19.0f);
    }

    @Override // android.graphics.drawable.Drawable
    public int getIntrinsicHeight() {
        return AndroidUtilities.dp(19.0f);
    }
}
