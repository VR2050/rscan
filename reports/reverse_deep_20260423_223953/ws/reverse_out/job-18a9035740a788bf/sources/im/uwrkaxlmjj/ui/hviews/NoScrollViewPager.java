package im.uwrkaxlmjj.ui.hviews;

import android.content.Context;
import android.util.AttributeSet;
import android.view.MotionEvent;
import androidx.viewpager.widget.ViewPager;
import im.uwrkaxlmjj.ui.actionbar.Theme;

/* JADX INFO: loaded from: classes5.dex */
public class NoScrollViewPager extends ViewPager {
    private boolean enScroll;

    public NoScrollViewPager(Context context) {
        super(context);
        this.enScroll = false;
    }

    public NoScrollViewPager(Context context, AttributeSet attrs) {
        super(context, attrs);
        this.enScroll = false;
        setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
    }

    @Override // android.view.ViewGroup, android.view.View
    public boolean dispatchTouchEvent(MotionEvent ev) {
        return super.dispatchTouchEvent(ev);
    }

    @Override // androidx.viewpager.widget.ViewPager, android.view.ViewGroup
    public boolean onInterceptTouchEvent(MotionEvent ev) {
        try {
            if (this.enScroll) {
                return super.onInterceptTouchEvent(ev);
            }
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    @Override // androidx.viewpager.widget.ViewPager, android.view.View
    public boolean onTouchEvent(MotionEvent ev) {
        try {
            if (this.enScroll) {
                return super.onTouchEvent(ev);
            }
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    public void setEnScroll(boolean enScroll) {
        this.enScroll = enScroll;
    }
}
