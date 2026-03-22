package com.angcyo.tablayout;

import android.view.GestureDetector;
import android.view.MotionEvent;
import com.angcyo.tablayout.DslTabLayout;
import kotlin.Metadata;
import org.jetbrains.annotations.Nullable;

@Metadata(m5310d1 = {"\u0000!\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000b\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0007\n\u0002\b\u0005*\u0001\u0000\b\n\u0018\u00002\u00020\u0001J,\u0010\u0002\u001a\u00020\u00032\b\u0010\u0004\u001a\u0004\u0018\u00010\u00052\b\u0010\u0006\u001a\u0004\u0018\u00010\u00052\u0006\u0010\u0007\u001a\u00020\b2\u0006\u0010\t\u001a\u00020\bH\u0016J,\u0010\n\u001a\u00020\u00032\b\u0010\u0004\u001a\u0004\u0018\u00010\u00052\b\u0010\u0006\u001a\u0004\u0018\u00010\u00052\u0006\u0010\u000b\u001a\u00020\b2\u0006\u0010\f\u001a\u00020\bH\u0016¨\u0006\r"}, m5311d2 = {"com/angcyo/tablayout/DslTabLayout$_gestureDetector$2$1", "Landroid/view/GestureDetector$SimpleOnGestureListener;", "onFling", "", "e1", "Landroid/view/MotionEvent;", "e2", "velocityX", "", "velocityY", "onScroll", "distanceX", "distanceY", "TabLayout_release"}, m5312k = 1, m5313mv = {1, 6, 0}, m5315xi = 48)
/* renamed from: b.e.a.q */
/* loaded from: classes.dex */
public final class C1520q extends GestureDetector.SimpleOnGestureListener {

    /* renamed from: c */
    public final /* synthetic */ DslTabLayout f1647c;

    public C1520q(DslTabLayout dslTabLayout) {
        this.f1647c = dslTabLayout;
    }

    @Override // android.view.GestureDetector.SimpleOnGestureListener, android.view.GestureDetector.OnGestureListener
    public boolean onFling(@Nullable MotionEvent e1, @Nullable MotionEvent e2, float velocityX, float velocityY) {
        if (this.f1647c.m3866d()) {
            if (Math.abs(velocityX) <= this.f1647c.getF8745C()) {
                return true;
            }
            this.f1647c.m3870j(velocityX);
            return true;
        }
        if (Math.abs(velocityY) <= this.f1647c.getF8745C()) {
            return true;
        }
        this.f1647c.m3870j(velocityY);
        return true;
    }

    @Override // android.view.GestureDetector.SimpleOnGestureListener, android.view.GestureDetector.OnGestureListener
    public boolean onScroll(@Nullable MotionEvent e1, @Nullable MotionEvent e2, float distanceX, float distanceY) {
        if (this.f1647c.m3866d()) {
            if (Math.abs(distanceX) > this.f1647c.getF8747E()) {
                return this.f1647c.m3872l(distanceX);
            }
        } else if (Math.abs(distanceY) > this.f1647c.getF8747E()) {
            return this.f1647c.m3872l(distanceY);
        }
        return false;
    }
}
