package im.uwrkaxlmjj.ui.hviews.helper;

import android.R;
import android.app.Activity;
import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.res.Configuration;
import android.content.res.Resources;
import android.graphics.Point;
import android.net.ConnectivityManager;
import android.os.Build;
import android.os.Environment;
import android.provider.Settings;
import android.util.DisplayMetrics;
import android.util.TypedValue;
import android.view.Display;
import android.view.KeyCharacterMap;
import android.view.View;
import android.view.ViewConfiguration;
import android.view.Window;
import android.view.WindowManager;
import im.uwrkaxlmjj.messenger.utils.status.StatusBarUtils;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Locale;

/* JADX INFO: loaded from: classes5.dex */
public class MryDisplayHelper {
    private static final String HUAWAI_DISPLAY_NOTCH_STATUS = "display_notch_status";
    private static final String TAG = "QMUIDisplayHelper";
    private static final String VIVO_NAVIGATION_GESTURE = "navigation_gesture_on";
    private static final String XIAOMI_DISPLAY_NOTCH_STATUS = "force_black";
    private static final String XIAOMI_FULLSCREEN_GESTURE = "force_fsg_nav_bar";
    public static final float DENSITY = Resources.getSystem().getDisplayMetrics().density;
    private static Boolean sHasCamera = null;

    public static DisplayMetrics getDisplayMetrics(Context context) {
        return context.getResources().getDisplayMetrics();
    }

    public static int dpToPx(int dpValue) {
        return (int) ((dpValue * DENSITY) + 0.5f);
    }

    public static int pxToDp(float pxValue) {
        return (int) ((pxValue / DENSITY) + 0.5f);
    }

    public static float getDensity(Context context) {
        return context.getResources().getDisplayMetrics().density;
    }

    public static float getFontDensity(Context context) {
        return context.getResources().getDisplayMetrics().scaledDensity;
    }

    public static int getScreenWidth(Context context) {
        return getDisplayMetrics(context).widthPixels;
    }

    public static int getScreenHeight(Context context) {
        int screenHeight = getDisplayMetrics(context).heightPixels;
        if (MryDeviceHelper.isXiaomi() && xiaomiNavigationGestureEnabled(context)) {
            return screenHeight + getResourceNavHeight(context);
        }
        return screenHeight;
    }

    public static int[] getRealScreenSize(Context context) {
        return doGetRealScreenSize(context);
    }

    private static int[] doGetRealScreenSize(Context context) {
        int[] size = new int[2];
        WindowManager w = (WindowManager) context.getSystemService("window");
        Display d = w.getDefaultDisplay();
        DisplayMetrics metrics = new DisplayMetrics();
        d.getMetrics(metrics);
        int widthPixels = metrics.widthPixels;
        int heightPixels = metrics.heightPixels;
        try {
            widthPixels = ((Integer) Display.class.getMethod("getRawWidth", new Class[0]).invoke(d, new Object[0])).intValue();
            heightPixels = ((Integer) Display.class.getMethod("getRawHeight", new Class[0]).invoke(d, new Object[0])).intValue();
        } catch (Exception e) {
        }
        if (Build.VERSION.SDK_INT >= 17) {
            try {
                Point realSize = new Point();
                d.getRealSize(realSize);
                Display.class.getMethod("getRealSize", Point.class).invoke(d, realSize);
                widthPixels = realSize.x;
                heightPixels = realSize.y;
            } catch (Exception e2) {
            }
        }
        size[0] = widthPixels;
        size[1] = heightPixels;
        return size;
    }

    public static int getUsefulScreenWidth(Activity activity) {
        return getUsefulScreenWidth(activity, MryNotchHelper.hasNotch(activity));
    }

    public static int getUsefulScreenWidth(View view) {
        return getUsefulScreenWidth(view.getContext(), MryNotchHelper.hasNotch(view));
    }

    public static int getUsefulScreenWidth(Context context, boolean hasNotch) {
        int result = getRealScreenSize(context)[0];
        int orientation = context.getResources().getConfiguration().orientation;
        boolean isLandscape = orientation == 2;
        if (!hasNotch) {
            if (isLandscape && MryDeviceHelper.isEssentialPhone() && Build.VERSION.SDK_INT < 26) {
                return result - (StatusBarUtils.getStatusBarHeight(context) * 2);
            }
            return result;
        }
        if (isLandscape && MryDeviceHelper.isHuawei() && !huaweiIsNotchSetToShowInSetting(context)) {
            return result - MryNotchHelper.getNotchSizeInHuawei(context)[1];
        }
        return result;
    }

    public static int getUsefulScreenHeight(Activity activity) {
        return getUsefulScreenHeight(activity, MryNotchHelper.hasNotch(activity));
    }

    public static int getUsefulScreenHeight(View view) {
        return getUsefulScreenHeight(view.getContext(), MryNotchHelper.hasNotch(view));
    }

    private static int getUsefulScreenHeight(Context context, boolean hasNotch) {
        int result = getRealScreenSize(context)[1];
        int orientation = context.getResources().getConfiguration().orientation;
        boolean isPortrait = orientation == 1;
        if (!hasNotch && isPortrait && MryDeviceHelper.isEssentialPhone() && Build.VERSION.SDK_INT < 26) {
            return result - (StatusBarUtils.getStatusBarHeight(context) * 2);
        }
        return result;
    }

    public static boolean isNavMenuExist(Context context) {
        boolean hasMenuKey = ViewConfiguration.get(context).hasPermanentMenuKey();
        boolean hasBackKey = KeyCharacterMap.deviceHasKey(4);
        if (!hasMenuKey && !hasBackKey) {
            return true;
        }
        return false;
    }

    public static int dp2px(Context context, int dp) {
        return (int) (((double) (getDensity(context) * dp)) + 0.5d);
    }

    public static int sp2px(Context context, int sp) {
        return (int) (((double) (getFontDensity(context) * sp)) + 0.5d);
    }

    public static int px2dp(Context context, int px) {
        return (int) (((double) (px / getDensity(context))) + 0.5d);
    }

    public static int px2sp(Context context, int px) {
        return (int) (((double) (px / getFontDensity(context))) + 0.5d);
    }

    public static boolean hasStatusBar(Context context) {
        if (!(context instanceof Activity)) {
            return true;
        }
        Activity activity = (Activity) context;
        WindowManager.LayoutParams attrs = activity.getWindow().getAttributes();
        return (attrs.flags & 1024) != 1024;
    }

    public static int getActionBarHeight(Context context) {
        TypedValue tv = new TypedValue();
        if (!context.getTheme().resolveAttribute(R.attr.actionBarSize, tv, true)) {
            return 0;
        }
        int actionBarHeight = TypedValue.complexToDimensionPixelSize(tv.data, context.getResources().getDisplayMetrics());
        return actionBarHeight;
    }

    public static int getStatusBarHeight(Context context) {
        if (MryDeviceHelper.isXiaomi()) {
            int resourceId = context.getResources().getIdentifier("status_bar_height", "dimen", "android");
            if (resourceId > 0) {
                return context.getResources().getDimensionPixelSize(resourceId);
            }
            return 0;
        }
        try {
            Class<?> c = Class.forName("com.android.internal.R$dimen");
            Object obj = c.newInstance();
            Field field = c.getField("status_bar_height");
            int x = Integer.parseInt(field.get(obj).toString());
            if (x > 0) {
                return context.getResources().getDimensionPixelSize(x);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return 0;
    }

    public static int getNavMenuHeight(Context context) {
        if (!isNavMenuExist(context)) {
            return 0;
        }
        int resourceNavHeight = getResourceNavHeight(context);
        if (resourceNavHeight >= 0) {
            return resourceNavHeight;
        }
        return getRealScreenSize(context)[1] - getScreenHeight(context);
    }

    private static int getResourceNavHeight(Context context) {
        int resourceId = context.getResources().getIdentifier("navigation_bar_height", "dimen", "android");
        if (resourceId > 0) {
            return context.getResources().getDimensionPixelSize(resourceId);
        }
        return -1;
    }

    public static final boolean hasCamera(Context context) {
        if (sHasCamera == null) {
            PackageManager pckMgr = context.getPackageManager();
            boolean flag = pckMgr.hasSystemFeature("android.hardware.camera.front");
            boolean flag1 = pckMgr.hasSystemFeature("android.hardware.camera");
            boolean flag2 = flag || flag1;
            sHasCamera = Boolean.valueOf(flag2);
        }
        return sHasCamera.booleanValue();
    }

    public static boolean hasHardwareMenuKey(Context context) {
        if (Build.VERSION.SDK_INT < 11) {
            return true;
        }
        if (Build.VERSION.SDK_INT >= 14) {
            boolean flag = ViewConfiguration.get(context).hasPermanentMenuKey();
            return flag;
        }
        return false;
    }

    public static boolean hasInternet(Context context) {
        ConnectivityManager cm = (ConnectivityManager) context.getSystemService("connectivity");
        return cm.getActiveNetworkInfo() != null;
    }

    public static boolean isPackageExist(Context context, String pckName) {
        PackageInfo pckInfo;
        try {
            pckInfo = context.getPackageManager().getPackageInfo(pckName, 0);
        } catch (PackageManager.NameNotFoundException e) {
        }
        if (pckInfo == null) {
            return false;
        }
        return true;
    }

    public static boolean isSdcardReady() {
        return "mounted".equals(Environment.getExternalStorageState());
    }

    public static String getCurCountryLan(Context context) {
        Locale sysLocale;
        Configuration config = context.getResources().getConfiguration();
        if (Build.VERSION.SDK_INT >= 24) {
            sysLocale = config.getLocales().get(0);
        } else {
            sysLocale = config.locale;
        }
        return sysLocale.getLanguage() + "-" + sysLocale.getCountry();
    }

    public static boolean isZhCN(Context context) {
        Locale sysLocale;
        Configuration config = context.getResources().getConfiguration();
        if (Build.VERSION.SDK_INT >= 24) {
            sysLocale = config.getLocales().get(0);
        } else {
            sysLocale = config.locale;
        }
        String lang = sysLocale.getCountry();
        return lang.equalsIgnoreCase("CN");
    }

    public static void setFullScreen(Activity activity) {
        Window window = activity.getWindow();
        window.addFlags(512);
        window.addFlags(1024);
    }

    public static void cancelFullScreen(Activity activity) {
        Window window = activity.getWindow();
        window.clearFlags(1024);
        window.clearFlags(512);
    }

    public static boolean isFullScreen(Activity activity) {
        WindowManager.LayoutParams params = activity.getWindow().getAttributes();
        return (params.flags & 1024) == 1024;
    }

    public static boolean isElevationSupported() {
        return Build.VERSION.SDK_INT >= 21;
    }

    public static boolean hasNavigationBar(Context context) {
        boolean hasNav = deviceHasNavigationBar();
        if (!hasNav) {
            return false;
        }
        if (MryDeviceHelper.isVivo()) {
            return vivoNavigationGestureEnabled(context);
        }
        return true;
    }

    private static boolean deviceHasNavigationBar() {
        try {
            Class<?> windowManagerGlobalClass = Class.forName("android.view.WindowManagerGlobal");
            Method getWmServiceMethod = windowManagerGlobalClass.getDeclaredMethod("getWindowManagerService", new Class[0]);
            getWmServiceMethod.setAccessible(true);
            Object iWindowManager = getWmServiceMethod.invoke(null, new Object[0]);
            Class<?> iWindowManagerClass = iWindowManager.getClass();
            Method hasNavBarMethod = iWindowManagerClass.getDeclaredMethod("hasNavigationBar", new Class[0]);
            hasNavBarMethod.setAccessible(true);
            boolean haveNav = ((Boolean) hasNavBarMethod.invoke(iWindowManager, new Object[0])).booleanValue();
            return haveNav;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    public static boolean vivoNavigationGestureEnabled(Context context) {
        int val = Settings.Secure.getInt(context.getContentResolver(), VIVO_NAVIGATION_GESTURE, 0);
        return val != 0;
    }

    public static boolean xiaomiNavigationGestureEnabled(Context context) {
        int val = Settings.Global.getInt(context.getContentResolver(), XIAOMI_FULLSCREEN_GESTURE, 0);
        return val != 0;
    }

    public static boolean huaweiIsNotchSetToShowInSetting(Context context) {
        int result = Settings.Secure.getInt(context.getContentResolver(), HUAWAI_DISPLAY_NOTCH_STATUS, 0);
        return result == 0;
    }

    public static boolean xiaomiIsNotchSetToShowInSetting(Context context) {
        return Settings.Global.getInt(context.getContentResolver(), XIAOMI_DISPLAY_NOTCH_STATUS, 0) == 0;
    }
}
