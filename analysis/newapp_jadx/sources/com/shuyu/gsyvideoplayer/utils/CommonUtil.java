package com.shuyu.gsyvideoplayer.utils;

import android.R;
import android.annotation.SuppressLint;
import android.app.Activity;
import android.content.Context;
import android.content.ContextWrapper;
import android.net.ConnectivityManager;
import android.os.Build;
import android.util.DisplayMetrics;
import android.util.TypedValue;
import android.view.WindowManager;
import androidx.appcompat.app.ActionBar;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.view.ContextThemeWrapper;
import androidx.appcompat.widget.TintContextWrapper;
import androidx.fragment.app.FragmentActivity;
import com.gyf.immersionbar.Constants;
import java.io.File;
import java.util.Formatter;
import java.util.Locale;
import p005b.p131d.p132a.p133a.C1499a;
import tv.danmaku.ijk.media.player.IjkMediaMeta;

/* loaded from: classes2.dex */
public class CommonUtil {
    public static void deleteFile(String str) {
        File file = new File(str);
        if (file.exists()) {
            if (file.isFile()) {
                file.delete();
                return;
            }
            for (String str2 : file.list()) {
                StringBuilder m586H = C1499a.m586H(str);
                m586H.append(File.separator);
                m586H.append(str2);
                deleteFile(m586H.toString());
            }
            file.delete();
        }
    }

    public static int dip2px(Context context, float f2) {
        return (int) ((f2 * context.getResources().getDisplayMetrics().density) + 0.5f);
    }

    public static int getActionBarHeight(Activity activity) {
        TypedValue typedValue = new TypedValue();
        if (activity.getTheme().resolveAttribute(R.attr.actionBarSize, typedValue, true)) {
            return TypedValue.complexToDimensionPixelSize(typedValue.data, activity.getResources().getDisplayMetrics());
        }
        return 0;
    }

    public static Activity getActivityContext(Context context) {
        if (context == null) {
            return null;
        }
        if (context instanceof Activity) {
            return (Activity) context;
        }
        if (context instanceof TintContextWrapper) {
            return scanForActivity(((TintContextWrapper) context).getBaseContext());
        }
        if (context instanceof ContextWrapper) {
            return scanForActivity(((ContextWrapper) context).getBaseContext());
        }
        return null;
    }

    public static AppCompatActivity getAppCompActivity(Context context) {
        if (context == null) {
            return null;
        }
        if (context instanceof AppCompatActivity) {
            return (AppCompatActivity) context;
        }
        if (context instanceof ContextThemeWrapper) {
            return getAppCompActivity(((ContextThemeWrapper) context).getBaseContext());
        }
        return null;
    }

    public static boolean getCurrentScreenLand(Activity activity) {
        return activity.getWindowManager().getDefaultDisplay().getRotation() == 1 || activity.getWindowManager().getDefaultDisplay().getRotation() == 3;
    }

    public static int getScreenHeight(Context context) {
        WindowManager windowManager = (WindowManager) context.getSystemService("window");
        DisplayMetrics displayMetrics = new DisplayMetrics();
        windowManager.getDefaultDisplay().getMetrics(displayMetrics);
        return displayMetrics.heightPixels;
    }

    public static int getScreenWidth(Context context) {
        WindowManager windowManager = (WindowManager) context.getSystemService("window");
        DisplayMetrics displayMetrics = new DisplayMetrics();
        windowManager.getDefaultDisplay().getMetrics(displayMetrics);
        return displayMetrics.widthPixels;
    }

    public static int getStatusBarHeight(Context context) {
        int identifier = context.getResources().getIdentifier(Constants.IMMERSION_STATUS_BAR_HEIGHT, "dimen", "android");
        if (identifier > 0) {
            return context.getResources().getDimensionPixelSize(identifier);
        }
        return 0;
    }

    public static String getTextSpeed(long j2) {
        if (j2 >= 0 && j2 < IjkMediaMeta.AV_CH_SIDE_RIGHT) {
            return j2 + " KB/s";
        }
        if (j2 >= IjkMediaMeta.AV_CH_SIDE_RIGHT && j2 < 1048576) {
            return Long.toString(j2 / IjkMediaMeta.AV_CH_SIDE_RIGHT) + " KB/s";
        }
        if (j2 < 1048576 || j2 >= IjkMediaMeta.AV_CH_STEREO_RIGHT) {
            return "";
        }
        return Long.toString(j2 / 1048576) + " MB/s";
    }

    public static void hideNavKey(Context context) {
        if (Build.VERSION.SDK_INT >= 29) {
            ((Activity) context).getWindow().getDecorView().setSystemUiVisibility(3074);
        } else {
            ((Activity) context).getWindow().getDecorView().setSystemUiVisibility(2562);
        }
    }

    @SuppressLint({"RestrictedApi"})
    public static void hideSupportActionBar(Context context, boolean z, boolean z2) {
        AppCompatActivity appCompActivity;
        ActionBar supportActionBar;
        if (z && (appCompActivity = getAppCompActivity(context)) != null && (supportActionBar = appCompActivity.getSupportActionBar()) != null) {
            supportActionBar.setShowHideAnimationEnabled(false);
            supportActionBar.hide();
        }
        if (z2) {
            if (context instanceof FragmentActivity) {
                ((FragmentActivity) context).getWindow().setFlags(1024, 1024);
            } else if (context instanceof Activity) {
                ((Activity) context).getWindow().setFlags(1024, 1024);
            } else {
                getAppCompActivity(context).getWindow().setFlags(1024, 1024);
            }
        }
    }

    public static boolean isWifiConnected(Context context) {
        return ((ConnectivityManager) context.getSystemService("connectivity")).getNetworkInfo(1).isConnected();
    }

    public static int px2dip(Context context, float f2) {
        return (int) ((f2 / context.getResources().getDisplayMetrics().density) + 0.5f);
    }

    public static Activity scanForActivity(Context context) {
        if (context == null) {
            return null;
        }
        if (context instanceof Activity) {
            return (Activity) context;
        }
        if (context instanceof TintContextWrapper) {
            return scanForActivity(((TintContextWrapper) context).getBaseContext());
        }
        if (context instanceof ContextWrapper) {
            return scanForActivity(((ContextWrapper) context).getBaseContext());
        }
        return null;
    }

    public static void showNavKey(Context context, int i2) {
        ((Activity) context).getWindow().getDecorView().setSystemUiVisibility(i2);
    }

    @SuppressLint({"RestrictedApi"})
    public static void showSupportActionBar(Context context, boolean z, boolean z2) {
        AppCompatActivity appCompActivity;
        ActionBar supportActionBar;
        if (z && (appCompActivity = getAppCompActivity(context)) != null && (supportActionBar = appCompActivity.getSupportActionBar()) != null) {
            supportActionBar.setShowHideAnimationEnabled(false);
            supportActionBar.show();
        }
        if (z2) {
            if (context instanceof FragmentActivity) {
                ((FragmentActivity) context).getWindow().clearFlags(1024);
            } else if (context instanceof Activity) {
                ((Activity) context).getWindow().clearFlags(1024);
            } else {
                getAppCompActivity(context).getWindow().clearFlags(1024);
            }
        }
    }

    public static String stringForTime(int i2) {
        if (i2 <= 0 || i2 >= 86400000) {
            return "00:00";
        }
        int i3 = i2 / 1000;
        int i4 = i3 % 60;
        int i5 = (i3 / 60) % 60;
        int i6 = i3 / 3600;
        Formatter formatter = new Formatter(new StringBuilder(), Locale.getDefault());
        return i6 > 0 ? formatter.format("%d:%02d:%02d", Integer.valueOf(i6), Integer.valueOf(i5), Integer.valueOf(i4)).toString() : formatter.format("%02d:%02d", Integer.valueOf(i5), Integer.valueOf(i4)).toString();
    }
}
