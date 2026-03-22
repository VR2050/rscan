package com.huxq17.floatball.libarary.menu;

import android.view.MotionEvent;
import android.view.ViewTreeObserver;
import android.widget.FrameLayout;

/* loaded from: classes2.dex */
public class FloatMenu extends FrameLayout {
    public int getSize() {
        return 0;
    }

    @Override // android.view.View
    public boolean onTouchEvent(MotionEvent motionEvent) {
        int action = motionEvent.getAction();
        motionEvent.getRawX();
        motionEvent.getRawY();
        if (action == 1 || action == 3 || action == 4) {
            throw null;
        }
        return super.onTouchEvent(motionEvent);
    }

    public void removeViewTreeObserver(ViewTreeObserver.OnGlobalLayoutListener onGlobalLayoutListener) {
        getViewTreeObserver().removeOnGlobalLayoutListener(onGlobalLayoutListener);
    }
}
