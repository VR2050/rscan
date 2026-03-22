package com.yalantis.ucrop.callback;

import android.graphics.RectF;

/* loaded from: classes2.dex */
public interface OverlayViewChangeListener {
    void onCropRectUpdated(RectF rectF);

    void postTranslate(float f2, float f3);
}
