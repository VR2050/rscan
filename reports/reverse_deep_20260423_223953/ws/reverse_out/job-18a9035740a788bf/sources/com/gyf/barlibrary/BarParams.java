package com.gyf.barlibrary;

import android.database.ContentObserver;
import android.view.View;
import java.util.HashMap;
import java.util.Map;

/* JADX INFO: loaded from: classes.dex */
public class BarParams implements Cloneable {
    public int flymeOSStatusBarFontColor;
    public KeyboardPatch keyboardPatch;
    public View navigationBarView;
    public ContentObserver navigationStatusObserver;
    public OnKeyboardListener onKeyboardListener;
    public View statusBarView;
    public View statusBarViewByHeight;
    public int titleBarHeight;
    public int titleBarPaddingTopHeight;
    public View titleBarView;
    public View titleBarViewMarginTop;
    public int statusBarColor = 0;
    public int navigationBarColor = -16777216;
    public float statusBarAlpha = 0.0f;
    float navigationBarAlpha = 0.0f;
    public boolean fullScreen = false;
    public boolean fullScreenTemp = false;
    public BarHide barHide = BarHide.FLAG_SHOW_BAR;
    public boolean darkFont = false;
    public boolean statusBarFlag = true;
    public int statusBarColorTransform = -16777216;
    public int navigationBarColorTransform = -16777216;
    public Map<View, Map<Integer, Integer>> viewMap = new HashMap();
    public float viewAlpha = 0.0f;
    public boolean fits = false;
    public int statusBarColorContentView = 0;
    public int statusBarColorContentViewTransform = -16777216;
    public float statusBarContentViewAlpha = 0.0f;
    public int navigationBarColorTemp = this.navigationBarColor;
    public boolean isSupportActionBar = false;
    public boolean titleBarViewMarginTopFlag = false;
    public boolean keyboardEnable = false;
    public int keyboardMode = 18;
    public boolean navigationBarEnable = true;
    public boolean navigationBarWithKitkatEnable = true;

    @Deprecated
    public boolean fixMarginAtBottom = false;
    public boolean systemWindows = false;

    /* JADX INFO: Access modifiers changed from: protected */
    /* JADX INFO: renamed from: clone, reason: merged with bridge method [inline-methods] */
    public BarParams m15clone() {
        try {
            BarParams barParams = (BarParams) super.clone();
            return barParams;
        } catch (CloneNotSupportedException e) {
            e.printStackTrace();
            return null;
        }
    }
}
