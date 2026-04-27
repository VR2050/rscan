package im.uwrkaxlmjj.ui.hui.friendscircle_v1.view;

import android.content.Context;
import android.text.Layout;
import android.text.Spannable;
import android.text.TextPaint;
import android.text.style.ClickableSpan;
import android.util.AttributeSet;
import android.view.MotionEvent;
import android.view.ViewConfiguration;
import androidx.appcompat.widget.AppCompatTextView;

/* JADX INFO: loaded from: classes5.dex */
public class ControlClickSpanTextView extends AppCompatTextView {
    private long downTime;

    public ControlClickSpanTextView(Context context) {
        super(context);
    }

    public ControlClickSpanTextView(Context context, AttributeSet attrs) {
        super(context, attrs);
    }

    public ControlClickSpanTextView(Context context, AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
    }

    @Override // android.widget.TextView, android.view.View
    public boolean onTouchEvent(MotionEvent event) {
        int action = event.getAction();
        if (action == 0) {
            this.downTime = System.currentTimeMillis();
        }
        if (action == 1) {
            long interval = System.currentTimeMillis() - this.downTime;
            int x = (int) event.getX();
            int y = (int) event.getY();
            int x2 = x - getTotalPaddingLeft();
            int y2 = y - getTotalPaddingTop();
            int x3 = x2 + getScrollX();
            int y3 = y2 + getScrollY();
            Layout layout = getLayout();
            int line = layout.getLineForVertical(y3);
            int off = layout.getOffsetForHorizontal(line, x3);
            if (getText() instanceof Spannable) {
                Spannable buffer = (Spannable) getText();
                ClickableSpan[] link = (ClickableSpan[]) buffer.getSpans(off, off, ClickableSpan.class);
                if (link.length != 0 && interval < ViewConfiguration.getLongPressTimeout()) {
                    TextPaint paint = getPaint();
                    int lineStart = layout.getLineStart(line);
                    int lineEnd = layout.getLineEnd(line);
                    CharSequence charSequence = getText().subSequence(lineStart, lineEnd);
                    float v = paint.measureText(charSequence.toString());
                    if (x3 <= v) {
                        link[0].onClick(this);
                        return true;
                    }
                }
            }
        }
        return super.onTouchEvent(event);
    }
}
