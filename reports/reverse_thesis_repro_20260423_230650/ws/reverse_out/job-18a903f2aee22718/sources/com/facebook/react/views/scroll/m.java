package com.facebook.react.views.scroll;

import android.view.MotionEvent;
import android.view.VelocityTracker;

/* JADX INFO: loaded from: classes.dex */
public final class m {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private VelocityTracker f8023a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private float f8024b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private float f8025c;

    public final void a(MotionEvent motionEvent) {
        t2.j.f(motionEvent, "ev");
        if (this.f8023a == null) {
            this.f8023a = VelocityTracker.obtain();
        }
        VelocityTracker velocityTracker = this.f8023a;
        if (velocityTracker != null) {
            velocityTracker.addMovement(motionEvent);
            int action = motionEvent.getAction() & 255;
            if (action == 1 || action == 3) {
                velocityTracker.computeCurrentVelocity(1);
                this.f8024b = velocityTracker.getXVelocity();
                this.f8025c = velocityTracker.getYVelocity();
                velocityTracker.recycle();
                this.f8023a = null;
            }
        }
    }

    public final float b() {
        return this.f8024b;
    }

    public final float c() {
        return this.f8025c;
    }
}
