package com.jbzd.media.movecartoons.view.page;

import android.content.Context;
import android.util.AttributeSet;
import android.view.MotionEvent;
import androidx.viewpager.widget.ViewPager;

/* loaded from: classes2.dex */
public class MyViewPager extends ViewPager {
    private boolean scrollble;

    public MyViewPager(Context context) {
        super(context);
        this.scrollble = true;
    }

    public boolean isScrollble() {
        return this.scrollble;
    }

    @Override // androidx.viewpager.widget.ViewPager, android.view.ViewGroup
    public boolean onInterceptTouchEvent(MotionEvent motionEvent) {
        if (this.scrollble) {
            return super.onInterceptTouchEvent(motionEvent);
        }
        return false;
    }

    @Override // androidx.viewpager.widget.ViewPager, android.view.View
    public boolean onTouchEvent(MotionEvent motionEvent) {
        if (this.scrollble) {
            return super.onTouchEvent(motionEvent);
        }
        return true;
    }

    public void setScrollble(boolean z) {
        this.scrollble = z;
    }

    public MyViewPager(Context context, AttributeSet attributeSet) {
        super(context, attributeSet);
        this.scrollble = true;
    }
}
