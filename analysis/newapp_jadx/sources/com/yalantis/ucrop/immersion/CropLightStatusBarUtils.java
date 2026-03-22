package com.yalantis.ucrop.immersion;

import android.annotation.TargetApi;
import android.app.Activity;
import android.os.Build;
import android.view.View;
import android.view.Window;
import android.view.WindowManager;
import com.gyf.immersionbar.Constants;
import java.lang.reflect.Field;
import java.lang.reflect.Method;

/* loaded from: classes2.dex */
public class CropLightStatusBarUtils {
    private static void initStatusBarStyle(Activity activity, boolean z, boolean z2) {
        if (z && z2) {
            activity.getWindow().getDecorView().setSystemUiVisibility(256);
            return;
        }
        if (!z && !z2) {
            activity.getWindow().getDecorView().setSystemUiVisibility(1280);
        } else {
            if (z || !z2) {
                return;
            }
            activity.getWindow().getDecorView().setSystemUiVisibility(1280);
        }
    }

    @TargetApi(11)
    private static void setAndroidNativeLightStatusBar(Activity activity, boolean z, boolean z2, boolean z3, boolean z4) {
        try {
            if (z3) {
                Window window = activity.getWindow();
                int i2 = Build.VERSION.SDK_INT;
                if (z && z2) {
                    if (!z4 || i2 < 23) {
                        window.getDecorView().setSystemUiVisibility(256);
                    } else {
                        window.getDecorView().setSystemUiVisibility(8448);
                    }
                } else if (z || z2) {
                    if (z || !z2) {
                        return;
                    }
                    if (!z4 || i2 < 23) {
                        window.getDecorView().setSystemUiVisibility(1280);
                    } else {
                        window.getDecorView().setSystemUiVisibility(9472);
                    }
                } else if (!z4 || i2 < 23) {
                    window.getDecorView().setSystemUiVisibility(1280);
                } else {
                    window.getDecorView().setSystemUiVisibility(9472);
                }
            } else {
                View decorView = activity.getWindow().getDecorView();
                if (!z4 || Build.VERSION.SDK_INT < 23) {
                    decorView.setSystemUiVisibility(0);
                } else {
                    decorView.setSystemUiVisibility(8192);
                }
            }
        } catch (Exception unused) {
        }
    }

    private static boolean setFlymeLightStatusBar(Activity activity, boolean z, boolean z2, boolean z3, boolean z4) {
        boolean z5 = true;
        if (activity == null) {
            return false;
        }
        initStatusBarStyle(activity, z, z2);
        try {
            WindowManager.LayoutParams attributes = activity.getWindow().getAttributes();
            Field declaredField = WindowManager.LayoutParams.class.getDeclaredField("MEIZU_FLAG_DARK_STATUS_BAR_ICON");
            Field declaredField2 = WindowManager.LayoutParams.class.getDeclaredField("meizuFlags");
            declaredField.setAccessible(true);
            declaredField2.setAccessible(true);
            int i2 = declaredField.getInt(null);
            int i3 = declaredField2.getInt(attributes);
            declaredField2.setInt(attributes, z4 ? i2 | i3 : (~i2) & i3);
            activity.getWindow().setAttributes(attributes);
            try {
                if (CropRomUtils.getFlymeVersion() < 7) {
                    return true;
                }
                setAndroidNativeLightStatusBar(activity, z, z2, z3, z4);
                return true;
            } catch (Exception unused) {
                setAndroidNativeLightStatusBar(activity, z, z2, z3, z4);
                return z5;
            }
        } catch (Exception unused2) {
            z5 = false;
        }
    }

    public static void setLightStatusBar(Activity activity, boolean z) {
        setLightStatusBar(activity, false, false, false, z);
    }

    public static void setLightStatusBarAboveAPI23(Activity activity, boolean z, boolean z2, boolean z3, boolean z4) {
        if (Build.VERSION.SDK_INT >= 23) {
            setLightStatusBar(activity, z, z2, z3, z4);
        }
    }

    private static boolean setMIUILightStatusBar(Activity activity, boolean z, boolean z2, boolean z3, boolean z4) {
        initStatusBarStyle(activity, z, z2);
        Class<?> cls = activity.getWindow().getClass();
        try {
            Class<?> cls2 = Class.forName("android.view.MiuiWindowManager$LayoutParams");
            int i2 = cls2.getField(Constants.IMMERSION_MIUI_STATUS_BAR_DARK).getInt(cls2);
            Class<?> cls3 = Integer.TYPE;
            Method method = cls.getMethod("setExtraFlags", cls3, cls3);
            Window window = activity.getWindow();
            Object[] objArr = new Object[2];
            objArr[0] = Integer.valueOf(z4 ? i2 : 0);
            objArr[1] = Integer.valueOf(i2);
            method.invoke(window, objArr);
            return true;
        } catch (Exception unused) {
            setAndroidNativeLightStatusBar(activity, z, z2, z3, z4);
            return false;
        }
    }

    public static void setLightStatusBar(Activity activity, boolean z, boolean z2, boolean z3, boolean z4) {
        int lightStatausBarAvailableRomType = CropRomUtils.getLightStatausBarAvailableRomType();
        if (lightStatausBarAvailableRomType == 1) {
            if (CropRomUtils.getMIUIVersionCode() >= 7) {
                setAndroidNativeLightStatusBar(activity, z, z2, z3, z4);
                return;
            } else {
                setMIUILightStatusBar(activity, z, z2, z3, z4);
                return;
            }
        }
        if (lightStatausBarAvailableRomType == 2) {
            setFlymeLightStatusBar(activity, z, z2, z3, z4);
        } else {
            if (lightStatausBarAvailableRomType != 3) {
                return;
            }
            setAndroidNativeLightStatusBar(activity, z, z2, z3, z4);
        }
    }
}
