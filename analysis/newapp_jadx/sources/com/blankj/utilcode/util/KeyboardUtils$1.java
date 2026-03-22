package com.blankj.utilcode.util;

import android.os.Bundle;
import android.os.ResultReceiver;
import android.view.inputmethod.InputMethodManager;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* loaded from: classes.dex */
public class KeyboardUtils$1 extends ResultReceiver {
    @Override // android.os.ResultReceiver
    public void onReceiveResult(int i2, Bundle bundle) {
        InputMethodManager inputMethodManager;
        if ((i2 == 1 || i2 == 3) && (inputMethodManager = (InputMethodManager) C4195m.m4792Y().getSystemService("input_method")) != null) {
            inputMethodManager.toggleSoftInput(0, 0);
        }
    }
}
