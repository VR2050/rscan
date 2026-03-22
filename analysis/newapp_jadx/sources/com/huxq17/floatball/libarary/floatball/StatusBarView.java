package com.huxq17.floatball.libarary.floatball;

import android.view.View;

/* loaded from: classes2.dex */
public class StatusBarView extends View {
    public int getStatusBarHeight() {
        int[] iArr = new int[2];
        int[] iArr2 = new int[2];
        getLocationInWindow(iArr);
        getLocationOnScreen(iArr2);
        return iArr2[1] - iArr[1];
    }

    @Override // android.view.View
    public void onMeasure(int i2, int i3) {
        super.onMeasure(i2, i3);
    }
}
