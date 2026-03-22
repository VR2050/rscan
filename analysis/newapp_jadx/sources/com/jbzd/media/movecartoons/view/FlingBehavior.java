package com.jbzd.media.movecartoons.view;

import android.content.Context;
import android.util.AttributeSet;
import android.view.MotionEvent;
import android.view.View;
import android.widget.OverScroller;
import androidx.coordinatorlayout.widget.CoordinatorLayout;
import androidx.core.view.ViewCompat;
import com.google.android.material.appbar.AppBarLayout;
import java.lang.reflect.Field;

/* loaded from: classes2.dex */
public class FlingBehavior extends AppBarLayout.Behavior {
    private OverScroller mScroller;

    public FlingBehavior() {
    }

    private void getSuperSuperField(Context context) {
        if (this.mScroller != null) {
            return;
        }
        try {
            Field declaredField = getClass().getSuperclass().getSuperclass().getSuperclass().getDeclaredField("scroller");
            declaredField.setAccessible(true);
            OverScroller overScroller = new OverScroller(context);
            this.mScroller = overScroller;
            declaredField.set(this, overScroller);
        } catch (Exception e2) {
            e2.toString();
            e2.printStackTrace();
        }
    }

    public FlingBehavior(Context context, AttributeSet attributeSet) {
        super(context, attributeSet);
        getSuperSuperField(context);
    }

    @Override // com.google.android.material.appbar.HeaderBehavior, androidx.coordinatorlayout.widget.CoordinatorLayout.Behavior
    public boolean onInterceptTouchEvent(CoordinatorLayout coordinatorLayout, AppBarLayout appBarLayout, MotionEvent motionEvent) {
        OverScroller overScroller;
        if (motionEvent.getAction() == 0 && (overScroller = this.mScroller) != null) {
            overScroller.abortAnimation();
        }
        return super.onInterceptTouchEvent(coordinatorLayout, (CoordinatorLayout) appBarLayout, motionEvent);
    }

    @Override // com.google.android.material.appbar.AppBarLayout.BaseBehavior, androidx.coordinatorlayout.widget.CoordinatorLayout.Behavior
    public void onNestedPreScroll(CoordinatorLayout coordinatorLayout, AppBarLayout appBarLayout, View view, int i2, int i3, int[] iArr, int i4) {
        if (this.mScroller != null && i4 == 1 && getTopAndBottomOffset() == 0) {
            ViewCompat.stopNestedScroll(view, i4);
        }
        super.onNestedPreScroll(coordinatorLayout, appBarLayout, view, i2, i3, iArr, i4);
    }
}
