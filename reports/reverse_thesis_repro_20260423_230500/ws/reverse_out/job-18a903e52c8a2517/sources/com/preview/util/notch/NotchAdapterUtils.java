package com.preview.util.notch;

import android.app.Activity;
import android.content.Context;
import android.graphics.Rect;
import android.os.Build;
import android.view.DisplayCutout;
import android.view.Window;
import android.view.WindowInsets;
import android.view.WindowManager;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.List;

/* JADX INFO: loaded from: classes2.dex */
public class NotchAdapterUtils {
    public static final String TAG = NotchAdapterUtils.class.getSimpleName();

    public static void adapter(Activity activity, int cutOutMode) {
        if (activity == null) {
            return;
        }
        adapter(activity.getWindow(), cutOutMode);
    }

    public static void adapter(Window window, int cutOutMode) {
        if (window == null || !isNotch(window)) {
            return;
        }
        if (Build.VERSION.SDK_INT >= 28) {
            adapterP(window, cutOutMode);
        } else if (Build.VERSION.SDK_INT >= 26) {
            adapterO(window, cutOutMode);
        }
    }

    private static void adapterP(Window window, int cutOutMode) {
        if (window == null) {
            return;
        }
        WindowManager.LayoutParams lp = window.getAttributes();
        lp.layoutInDisplayCutoutMode = cutOutMode;
        window.setAttributes(lp);
    }

    private static void adapterO(Window window, int cutOutMode) {
        if (window == null) {
            return;
        }
        if (OSUtils.isMiui()) {
            adapterOWithMIUI(window, cutOutMode);
        } else if (OSUtils.isEmui()) {
            adapterOWithEMUI(window, cutOutMode);
        }
    }

    private static void adapterOWithMIUI(Window window, int cutOutMode) {
        String methodName;
        if (window == null) {
            return;
        }
        if (cutOutMode == 2) {
            methodName = "clearExtraFlags";
        } else if (cutOutMode == 0) {
            WindowManager.LayoutParams attributes = window.getAttributes();
            if ((attributes.flags & ConnectionsManager.FileTypeFile) > 0) {
                methodName = "addExtraFlags";
            } else {
                methodName = "clearExtraFlags";
            }
        } else {
            methodName = "addExtraFlags";
        }
        try {
            Method method = Window.class.getMethod(methodName, Integer.TYPE);
            method.invoke(window, 768);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void adapterOWithEMUI(Window window, int cutOutMode) {
        String methodName;
        if (window == null) {
            return;
        }
        if (cutOutMode == 2) {
            methodName = "clearHwFlags";
        } else if (cutOutMode == 0) {
            WindowManager.LayoutParams attributes = window.getAttributes();
            if ((attributes.flags & ConnectionsManager.FileTypeFile) > 0) {
                methodName = "addHwFlags";
            } else {
                methodName = "clearHwFlags";
            }
        } else {
            methodName = "addHwFlags";
        }
        WindowManager.LayoutParams layoutParams = window.getAttributes();
        try {
            Class<?> cls = Class.forName("com.huawei.android.view.LayoutParamsEx");
            Object layoutParamsExObj = cls.getConstructor(WindowManager.LayoutParams.class).newInstance(layoutParams);
            Method method = cls.getMethod(methodName, Integer.TYPE);
            method.invoke(layoutParamsExObj, 65536);
        } catch (ClassNotFoundException e) {
            e = e;
            e.printStackTrace();
        } catch (IllegalAccessException e2) {
            e = e2;
            e.printStackTrace();
        } catch (InstantiationException e3) {
            e = e3;
            e.printStackTrace();
        } catch (NoSuchMethodException e4) {
            e = e4;
            e.printStackTrace();
        } catch (InvocationTargetException e5) {
            e = e5;
            e.printStackTrace();
        } catch (Exception e6) {
            e6.printStackTrace();
        }
    }

    public static boolean isNotch(Window window) {
        DisplayCutout displayCutout;
        List<Rect> rects;
        if (Build.VERSION.SDK_INT >= 28) {
            WindowInsets windowInsets = window.getDecorView().getRootWindowInsets();
            if (windowInsets == null || (displayCutout = windowInsets.getDisplayCutout()) == null || (rects = displayCutout.getBoundingRects()) == null || rects.size() <= 0) {
                return false;
            }
            return true;
        }
        boolean isNotchScreen = OSUtils.isMiui();
        if (isNotchScreen) {
            return isNotchOnMIUI();
        }
        if (OSUtils.isEmui()) {
            return isNotchOnEMUI(window.getContext());
        }
        if (OSUtils.isVivo()) {
            return isNotchOnVIVO(window.getContext());
        }
        if (OSUtils.isOppo()) {
            return isNotchOnOPPO(window.getContext());
        }
        return false;
    }

    public static boolean isNotchOnMIUI() {
        return "1".equals(OSUtils.getProp("ro.miui.notch"));
    }

    public static boolean isNotchOnEMUI(Context context) {
        if (context == null) {
            return false;
        }
        try {
            ClassLoader cl = context.getClassLoader();
            Class<?> clsLoadClass = cl.loadClass("com.huawei.android.util.HwNotchSizeUtil");
            Method get = clsLoadClass.getMethod("hasNotchOnHuawei", new Class[0]);
            boolean isNotch = ((Boolean) get.invoke(clsLoadClass, new Object[0])).booleanValue();
            return isNotch;
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
            return false;
        } catch (NoSuchMethodException e2) {
            e2.printStackTrace();
            return false;
        } catch (Exception e3) {
            e3.printStackTrace();
            return false;
        }
    }

    public static boolean isNotchOnVIVO(Context context) {
        if (context == null) {
            return false;
        }
        try {
            ClassLoader classLoader = context.getClassLoader();
            Class<?> clsLoadClass = classLoader.loadClass("android.util.FtFeature");
            Method method = clsLoadClass.getMethod("isFeatureSupport", Integer.TYPE);
            boolean isNotch = ((Boolean) method.invoke(clsLoadClass, 32)).booleanValue();
            return isNotch;
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
            return false;
        } catch (NoSuchMethodException e2) {
            e2.printStackTrace();
            return false;
        } catch (Exception e3) {
            e3.printStackTrace();
            return false;
        }
    }

    public static boolean isNotchOnOPPO(Context context) {
        if (context == null) {
            return false;
        }
        return context.getPackageManager().hasSystemFeature("com.oppo.feature.screen.heteromorphism");
    }
}
