package com.jbzd.media.movecartoons.view.tab;

import androidx.annotation.DrawableRes;

/* loaded from: classes2.dex */
public interface CustomTabEntity {
    @DrawableRes
    int getTabSelectedIcon();

    String getTabTitle();

    @DrawableRes
    int getTabUnselectedIcon();
}
