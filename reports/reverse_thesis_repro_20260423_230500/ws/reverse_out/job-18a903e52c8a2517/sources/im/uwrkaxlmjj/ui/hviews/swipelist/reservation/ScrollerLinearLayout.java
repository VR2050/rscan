package im.uwrkaxlmjj.ui.hviews.swipelist.reservation;

import android.content.Context;
import android.util.AttributeSet;
import android.widget.LinearLayout;
import android.widget.Scroller;

/* JADX INFO: loaded from: classes5.dex */
public class ScrollerLinearLayout extends LinearLayout implements ScrollerView {
    private final Scroller mScroller;

    public ScrollerLinearLayout(Context context) {
        this(context, null);
    }

    public ScrollerLinearLayout(Context context, AttributeSet attrs) {
        super(context, attrs);
        this.mScroller = new Scroller(context);
    }

    public Scroller getScroller() {
        return this.mScroller;
    }

    @Override // im.uwrkaxlmjj.ui.hviews.swipelist.reservation.ScrollerView
    public void smoothScrollBy(int dx, int dy, int duration) {
        if (dx == 0 && dy == 0) {
            this.mScroller.abortAnimation();
        } else {
            this.mScroller.startScroll(getScrollX(), getScrollY(), dx, dy, duration);
            invalidate();
        }
    }

    @Override // im.uwrkaxlmjj.ui.hviews.swipelist.reservation.ScrollerView
    public void smoothScrollTo(int x, int y, int duration) {
        int scrollX = getScrollX();
        int scrollY = getScrollY();
        boolean finished = this.mScroller.isFinished();
        if (!finished || (scrollX == x && scrollY == y)) {
            if (!finished) {
                if (this.mScroller.getFinalX() == x && this.mScroller.getFinalY() == y) {
                    return;
                }
            } else {
                return;
            }
        }
        int deltaX = x - scrollX;
        int deltaY = y - scrollY;
        smoothScrollBy(deltaX, deltaY, duration);
    }

    @Override // android.view.View
    public void computeScroll() {
        if (this.mScroller.computeScrollOffset()) {
            scrollTo(this.mScroller.getCurrX(), this.mScroller.getCurrY());
            invalidate();
        }
    }
}
