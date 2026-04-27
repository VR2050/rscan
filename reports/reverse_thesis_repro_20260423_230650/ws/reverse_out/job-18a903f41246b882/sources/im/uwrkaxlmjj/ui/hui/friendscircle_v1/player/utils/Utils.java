package im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.utils;

import android.app.Activity;
import android.content.Context;
import android.content.ContextWrapper;
import android.graphics.Point;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.os.Build;
import android.util.DisplayMetrics;
import android.util.Log;
import android.view.Display;
import android.view.View;
import android.view.WindowManager;
import com.king.zxing.util.LogUtils;

/* JADX INFO: loaded from: classes5.dex */
public class Utils {
    private static final String UNKNOWN_SIZE = "00:00";

    public static String formatVideoTimeLength(long miliseconds) {
        String strValueOf;
        String strValueOf2;
        String strValueOf3;
        String strValueOf4;
        String strValueOf5;
        Object objValueOf;
        int seconds = (int) (miliseconds / 1000);
        if (seconds == 0) {
            return UNKNOWN_SIZE;
        }
        if (seconds < 60) {
            StringBuilder sb = new StringBuilder();
            sb.append("00:");
            if (seconds < 10) {
                objValueOf = "0" + seconds;
            } else {
                objValueOf = Integer.valueOf(seconds);
            }
            sb.append(objValueOf);
            String formatLength = sb.toString();
            return formatLength;
        }
        if (seconds < 3600) {
            long sec = seconds % 60;
            long min = seconds / 60;
            StringBuilder sb2 = new StringBuilder();
            if (min < 10) {
                strValueOf4 = "0" + min;
            } else {
                strValueOf4 = String.valueOf(min);
            }
            sb2.append(strValueOf4);
            sb2.append(LogUtils.COLON);
            if (sec < 10) {
                strValueOf5 = "0" + sec;
            } else {
                strValueOf5 = String.valueOf(sec);
            }
            sb2.append(strValueOf5);
            String formatLength2 = sb2.toString();
            return formatLength2;
        }
        long hour = seconds / 3600;
        long min2 = (seconds % 3600) / 60;
        long sec2 = (seconds % 3600) % 60;
        StringBuilder sb3 = new StringBuilder();
        if (hour < 10) {
            strValueOf = "0" + hour;
        } else {
            strValueOf = String.valueOf(hour);
        }
        sb3.append(strValueOf);
        sb3.append(LogUtils.COLON);
        if (min2 < 10) {
            strValueOf2 = "0" + min2;
        } else {
            strValueOf2 = String.valueOf(min2);
        }
        sb3.append(strValueOf2);
        sb3.append(LogUtils.COLON);
        if (sec2 < 10) {
            strValueOf3 = "0" + sec2;
        } else {
            strValueOf3 = String.valueOf(sec2);
        }
        sb3.append(strValueOf3);
        String formatLength3 = sb3.toString();
        return formatLength3;
    }

    public static void showViewIfNeed(View view) {
        if (view.getVisibility() == 8 || view.getVisibility() == 4) {
            view.setVisibility(0);
        }
    }

    public static void hideViewIfNeed(View view) {
        if (view.getVisibility() == 0) {
            view.setVisibility(8);
        }
    }

    public static boolean isViewShown(View view) {
        return view.getVisibility() == 0;
    }

    public static boolean isViewHide(View view) {
        return view.getVisibility() == 8 || view.getVisibility() == 4;
    }

    public static void log(String message) {
        Log.d("__VideoPlayer__", message);
    }

    public static void logTouch(String message) {
        Log.d("__GestureTouch__", message);
    }

    public static Activity getActivity(Context context) {
        if (context == null) {
            return null;
        }
        if (context instanceof Activity) {
            return (Activity) context;
        }
        if (!(context instanceof ContextWrapper)) {
            return null;
        }
        return getActivity(((ContextWrapper) context).getBaseContext());
    }

    public static int getWindowWidth(Context context) {
        WindowManager windowManager = (WindowManager) context.getSystemService("window");
        Display display = windowManager.getDefaultDisplay();
        if (Build.VERSION.SDK_INT >= 17) {
            Point outPoint = new Point();
            display.getRealSize(outPoint);
            int screenWidthPixels = outPoint.x;
            return screenWidthPixels;
        }
        if (Build.VERSION.SDK_INT >= 13) {
            Point outPoint2 = new Point();
            display.getSize(outPoint2);
            int screenWidthPixels2 = outPoint2.x;
            return screenWidthPixels2;
        }
        int screenWidthPixels3 = display.getWidth();
        return screenWidthPixels3;
    }

    public static int getWindowHeight(Context context) {
        DisplayMetrics dm = new DisplayMetrics();
        ((Activity) context).getWindowManager().getDefaultDisplay().getMetrics(dm);
        return dm.heightPixels;
    }

    public static String getCacheDir(Context context) {
        return context.getExternalCacheDir().getAbsolutePath() + "/VideoCache";
    }

    public static boolean isConnected(Context context) {
        try {
            NetworkInfo net = ((ConnectivityManager) context.getSystemService("connectivity")).getActiveNetworkInfo();
            if (net != null) {
                if (net.isConnected()) {
                    return true;
                }
            }
            return false;
        } catch (Exception e) {
            return true;
        }
    }
}
