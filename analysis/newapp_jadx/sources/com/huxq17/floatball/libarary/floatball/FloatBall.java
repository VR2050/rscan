package com.huxq17.floatball.libarary.floatball;

import android.content.res.Configuration;
import android.view.MotionEvent;
import android.widget.FrameLayout;
import p005b.p299p.p300a.p301a.p302a.InterfaceC2716a;

/* loaded from: classes2.dex */
public class FloatBall extends FrameLayout implements InterfaceC2716a {

    /* renamed from: c */
    public boolean f9875c;

    @Override // p005b.p299p.p300a.p301a.p302a.InterfaceC2716a
    /* renamed from: a */
    public void mo3237a() {
    }

    @Override // p005b.p299p.p300a.p301a.p302a.InterfaceC2716a
    /* renamed from: b */
    public void mo3238b(int i2, int i3, int i4, int i5) {
        throw null;
    }

    public int getSize() {
        return 0;
    }

    @Override // android.view.View
    public void onConfigurationChanged(Configuration configuration) {
        super.onConfigurationChanged(configuration);
        this.f9875c = true;
        throw null;
    }

    @Override // android.widget.FrameLayout, android.view.ViewGroup, android.view.View
    public void onLayout(boolean z, int i2, int i3, int i4, int i5) {
        super.onLayout(z, i2, i3, i4, i5);
        throw null;
    }

    @Override // android.widget.FrameLayout, android.view.View
    public void onMeasure(int i2, int i3) {
        super.onMeasure(i2, i3);
        getMeasuredHeight();
        getMeasuredWidth();
        throw null;
    }

    @Override // android.view.View
    public boolean onTouchEvent(MotionEvent motionEvent) {
        motionEvent.getAction();
        motionEvent.getRawX();
        motionEvent.getRawY();
        throw null;
    }

    @Override // android.view.View
    public void onWindowVisibilityChanged(int i2) {
        super.onWindowVisibilityChanged(i2);
        if (i2 == 0) {
            onConfigurationChanged(null);
        }
    }
}
