package com.yalantis.ucrop.immersion;

import android.os.Build;
import android.view.Window;
import androidx.appcompat.app.AppCompatActivity;

/* loaded from: classes2.dex */
public class CropImmersiveManage {
    public static void immersiveAboveAPI23(AppCompatActivity appCompatActivity, int i2, int i3, boolean z) {
        if (Build.VERSION.SDK_INT >= 23) {
            immersiveAboveAPI23(appCompatActivity, false, false, i2, i3, z);
        }
    }

    public static boolean immersiveUseful() {
        return Build.VERSION.SDK_INT >= 23;
    }

    public static void immersiveAboveAPI23(AppCompatActivity appCompatActivity, boolean z, boolean z2, int i2, int i3, boolean z3) {
        try {
            Window window = appCompatActivity.getWindow();
            boolean z4 = true;
            if (z && z2) {
                window.clearFlags(201326592);
                CropLightStatusBarUtils.setLightStatusBar(appCompatActivity, true, true, i2 == 0, z3);
                window.addFlags(Integer.MIN_VALUE);
            } else if (!z && !z2) {
                window.clearFlags(201326592);
                if (i2 != 0) {
                    z4 = false;
                }
                CropLightStatusBarUtils.setLightStatusBar(appCompatActivity, false, false, z4, z3);
                window.addFlags(Integer.MIN_VALUE);
            } else {
                if (z) {
                    return;
                }
                window.clearFlags(201326592);
                CropLightStatusBarUtils.setLightStatusBar(appCompatActivity, false, true, i2 == 0, z3);
                window.addFlags(Integer.MIN_VALUE);
            }
            window.setStatusBarColor(i2);
            window.setNavigationBarColor(i3);
        } catch (Exception e2) {
            e2.printStackTrace();
        }
    }
}
