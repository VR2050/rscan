package com.gyf.immersionbar;

import android.view.View;
import androidx.annotation.ColorInt;
import androidx.annotation.FloatRange;
import androidx.core.view.ViewCompat;
import com.google.android.material.shadow.ShadowDrawableWrapper;
import java.util.HashMap;
import java.util.Map;

/* loaded from: classes2.dex */
public class BarParams implements Cloneable {

    @ColorInt
    public int flymeOSStatusBarFontColor;

    @ColorInt
    public int flymeOSStatusBarFontTempColor;
    public OnBarListener onBarListener;
    public OnKeyboardListener onKeyboardListener;
    public OnNavigationBarListener onNavigationBarListener;
    public View statusBarView;
    public View titleBarView;

    @ColorInt
    public int statusBarColor = 0;

    @ColorInt
    public int navigationBarColor = ViewCompat.MEASURED_STATE_MASK;
    public int defaultNavigationBarColor = ViewCompat.MEASURED_STATE_MASK;

    @FloatRange(from = ShadowDrawableWrapper.COS_45, m110to = 1.0d)
    public float statusBarAlpha = 0.0f;

    @FloatRange(from = ShadowDrawableWrapper.COS_45, m110to = 1.0d)
    public float statusBarTempAlpha = 0.0f;

    @FloatRange(from = ShadowDrawableWrapper.COS_45, m110to = 1.0d)
    public float navigationBarAlpha = 0.0f;

    @FloatRange(from = ShadowDrawableWrapper.COS_45, m110to = 1.0d)
    public float navigationBarTempAlpha = 0.0f;
    public boolean fullScreen = false;
    public boolean hideNavigationBar = false;
    public BarHide barHide = BarHide.FLAG_SHOW_BAR;
    public boolean statusBarDarkFont = false;
    public boolean navigationBarDarkIcon = false;
    public boolean autoStatusBarDarkModeEnable = false;
    public boolean autoNavigationBarDarkModeEnable = false;

    @FloatRange(from = ShadowDrawableWrapper.COS_45, m110to = 1.0d)
    public float autoStatusBarDarkModeAlpha = 0.0f;

    @FloatRange(from = ShadowDrawableWrapper.COS_45, m110to = 1.0d)
    public float autoNavigationBarDarkModeAlpha = 0.0f;
    public boolean statusBarColorEnabled = true;

    @ColorInt
    public int statusBarColorTransform = ViewCompat.MEASURED_STATE_MASK;

    @ColorInt
    public int navigationBarColorTransform = ViewCompat.MEASURED_STATE_MASK;
    public Map<View, Map<Integer, Integer>> viewMap = new HashMap();

    @FloatRange(from = ShadowDrawableWrapper.COS_45, m110to = 1.0d)
    public float viewAlpha = 0.0f;

    @ColorInt
    public int contentColor = 0;

    @ColorInt
    public int contentColorTransform = ViewCompat.MEASURED_STATE_MASK;

    @FloatRange(from = ShadowDrawableWrapper.COS_45, m110to = 1.0d)
    public float contentAlpha = 0.0f;
    public boolean fits = false;
    public boolean fitsLayoutOverlapEnable = true;
    public boolean isSupportActionBar = false;
    public boolean keyboardEnable = false;
    public int keyboardMode = 18;
    public boolean navigationBarEnable = true;
    public boolean navigationBarWithKitkatEnable = true;
    public boolean navigationBarWithEMUI3Enable = true;
    public boolean barEnable = true;

    /* renamed from: clone, reason: merged with bridge method [inline-methods] */
    public BarParams m5735clone() {
        try {
            return (BarParams) super.clone();
        } catch (CloneNotSupportedException unused) {
            return null;
        }
    }
}
