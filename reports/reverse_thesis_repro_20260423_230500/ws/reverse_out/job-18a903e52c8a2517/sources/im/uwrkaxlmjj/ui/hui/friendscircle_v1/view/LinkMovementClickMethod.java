package im.uwrkaxlmjj.ui.hui.friendscircle_v1.view;

import android.text.Layout;
import android.text.Selection;
import android.text.Spannable;
import android.text.TextPaint;
import android.text.method.LinkMovementMethod;
import android.text.style.ClickableSpan;
import android.view.MotionEvent;
import android.widget.TextView;

/* JADX INFO: loaded from: classes5.dex */
public class LinkMovementClickMethod extends LinkMovementMethod {
    private static final long CLICK_DELAY = 500;
    private static LinkMovementClickMethod sInstance;
    private long lastClickTime;

    @Override // android.text.method.LinkMovementMethod, android.text.method.ScrollingMovementMethod, android.text.method.BaseMovementMethod, android.text.method.MovementMethod
    public boolean onTouchEvent(TextView widget, Spannable buffer, MotionEvent event) {
        int action = event.getAction();
        if (action == 1 || action == 0) {
            int x = (int) event.getX();
            int y = (int) event.getY();
            int x2 = x - widget.getTotalPaddingLeft();
            int y2 = y - widget.getTotalPaddingTop();
            int x3 = x2 + widget.getScrollX();
            int y3 = y2 + widget.getScrollY();
            Layout layout = widget.getLayout();
            int line = layout.getLineForVertical(y3);
            int off = layout.getOffsetForHorizontal(line, x3);
            ClickableSpan[] link = (ClickableSpan[]) buffer.getSpans(off, off, ClickableSpan.class);
            if (link.length != 0) {
                if (action != 1) {
                    if (action == 0) {
                        Selection.setSelection(buffer, buffer.getSpanStart(link[0]), buffer.getSpanEnd(link[0]));
                        this.lastClickTime = System.currentTimeMillis();
                        return true;
                    }
                    return true;
                }
                if (System.currentTimeMillis() - this.lastClickTime < 500) {
                    TextPaint paint = widget.getPaint();
                    int lineStart = layout.getLineStart(line);
                    int lineEnd = layout.getLineEnd(line);
                    CharSequence charSequence = widget.getText().subSequence(lineStart, lineEnd);
                    float v = paint.measureText(charSequence.toString());
                    if (x3 <= v) {
                        link[0].onClick(widget);
                        return true;
                    }
                    return true;
                }
                return true;
            }
            Selection.removeSelection(buffer);
        }
        return super.onTouchEvent(widget, buffer, event);
    }

    public static LinkMovementClickMethod getInstance() {
        if (sInstance == null) {
            sInstance = new LinkMovementClickMethod();
        }
        return sInstance;
    }
}
