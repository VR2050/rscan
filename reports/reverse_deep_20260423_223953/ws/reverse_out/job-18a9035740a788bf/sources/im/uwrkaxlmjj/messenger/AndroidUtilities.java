package im.uwrkaxlmjj.messenger;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.AnimatorSet;
import android.animation.ObjectAnimator;
import android.app.Activity;
import android.app.ActivityManager;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.content.res.Configuration;
import android.database.ContentObserver;
import android.database.Cursor;
import android.graphics.Bitmap;
import android.graphics.Color;
import android.graphics.Matrix;
import android.graphics.Paint;
import android.graphics.Point;
import android.graphics.RectF;
import android.graphics.Typeface;
import android.graphics.drawable.BitmapDrawable;
import android.graphics.drawable.ColorDrawable;
import android.graphics.drawable.Drawable;
import android.hardware.camera2.CameraAccessException;
import android.hardware.camera2.CameraManager;
import android.net.Uri;
import android.os.Build;
import android.os.Environment;
import android.os.PowerManager;
import android.provider.CallLog;
import android.provider.Settings;
import android.renderscript.Allocation;
import android.renderscript.Element;
import android.renderscript.RenderScript;
import android.renderscript.ScriptIntrinsicBlur;
import android.telephony.PhoneNumberUtils;
import android.telephony.TelephonyManager;
import android.text.Selection;
import android.text.Spannable;
import android.text.SpannableStringBuilder;
import android.text.Spanned;
import android.text.SpannedString;
import android.text.TextUtils;
import android.text.method.LinkMovementMethod;
import android.text.method.PasswordTransformationMethod;
import android.text.style.ForegroundColorSpan;
import android.util.DisplayMetrics;
import android.util.StateSet;
import android.view.Display;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.view.WindowManager;
import android.view.accessibility.AccessibilityEvent;
import android.view.accessibility.AccessibilityManager;
import android.view.animation.AccelerateInterpolator;
import android.view.animation.DecelerateInterpolator;
import android.view.animation.OvershootInterpolator;
import android.view.inputmethod.InputMethodManager;
import android.webkit.MimeTypeMap;
import android.widget.EdgeEffect;
import android.widget.EditText;
import android.widget.HorizontalScrollView;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.ScrollView;
import android.widget.TextView;
import androidx.core.content.FileProvider;
import androidx.exifinterface.media.ExifInterface;
import androidx.viewpager.widget.ViewPager;
import com.android.internal.telephony.ITelephony;
import com.bumptech.glide.load.resource.bitmap.HardwareConfigState;
import com.google.android.exoplayer2.source.hls.DefaultHlsExtractorFactory;
import com.google.android.exoplayer2.text.ttml.TtmlNode;
import com.google.android.gms.auth.api.phone.SmsRetriever;
import com.google.android.gms.auth.api.phone.SmsRetrieverClient;
import com.google.android.gms.tasks.OnSuccessListener;
import com.google.android.gms.tasks.Task;
import com.google.firebase.remoteconfig.FirebaseRemoteConfig;
import com.just.agentweb.DefaultWebClient;
import com.litesuits.orm.db.assit.SQLBuilder;
import com.snail.antifake.deviceid.ShellAdbUtils;
import im.uwrkaxlmjj.messenger.SharedConfig;
import im.uwrkaxlmjj.phoneformat.PhoneFormat;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.ThemePreviewActivity;
import im.uwrkaxlmjj.ui.WallpapersListActivity;
import im.uwrkaxlmjj.ui.actionbar.AlertDialog;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.BottomSheet;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.cells.TextDetailSettingsCell;
import im.uwrkaxlmjj.ui.components.AlertsCreator;
import im.uwrkaxlmjj.ui.components.BackgroundGradientDrawable;
import im.uwrkaxlmjj.ui.components.ForegroundDetector;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.components.PickerBottomLayout;
import im.uwrkaxlmjj.ui.components.TypefaceSpan;
import im.uwrkaxlmjj.ui.hviews.swipelist.SlidingItemMenuRecyclerView;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.security.MessageDigest;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.Hashtable;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;
import kotlin.UByte;
import org.slf4j.Marker;

/* JADX INFO: loaded from: classes2.dex */
public class AndroidUtilities {
    public static final int FLAG_TAG_ALL = 11;
    public static final int FLAG_TAG_BOLD = 2;
    public static final int FLAG_TAG_BR = 1;
    public static final int FLAG_TAG_COLOR = 4;
    public static final int FLAG_TAG_URL = 8;
    public static Pattern WEB_URL;
    private static RectF bitmapRect;
    private static ContentObserver callLogContentObserver;
    private static int[] documentIcons;
    private static int[] documentMediaIcons;
    public static boolean firstConfigurationWas;
    private static boolean hasCallPermissions;
    public static boolean incorrectDisplaySizeFix;
    public static boolean isInMultiwindow;
    public static int leftBaseline;
    private static Field mAttachInfoField;
    private static Field mStableInsetsField;
    public static int roundMessageSize;
    private static Paint roundPaint;
    private static Runnable unregisterRunnable;
    public static boolean usingHardwareInput;
    private static final Hashtable<String, Typeface> typefaceCache = new Hashtable<>();
    private static int prevOrientation = -10;
    private static boolean waitingForSms = false;
    private static boolean waitingForCall = false;
    private static final Object smsLock = new Object();
    private static final Object callLock = new Object();
    public static int statusBarHeight = 0;
    public static float density = 1.0f;
    public static Point displaySize = new Point();
    public static Integer photoSize = null;
    public static DisplayMetrics displayMetrics = new DisplayMetrics();
    public static DecelerateInterpolator decelerateInterpolator = new DecelerateInterpolator();
    public static AccelerateInterpolator accelerateInterpolator = new AccelerateInterpolator();
    public static OvershootInterpolator overshootInterpolator = new OvershootInterpolator();
    private static Boolean isTablet = null;
    private static int adjustOwnerClassGuid = 0;

    static {
        WEB_URL = null;
        try {
            Pattern IP_ADDRESS = Pattern.compile("((25[0-5]|2[0-4][0-9]|[0-1][0-9]{2}|[1-9][0-9]|[1-9])\\.(25[0-5]|2[0-4][0-9]|[0-1][0-9]{2}|[1-9][0-9]|[1-9]|0)\\.(25[0-5]|2[0-4][0-9]|[0-1][0-9]{2}|[1-9][0-9]|[1-9]|0)\\.(25[0-5]|2[0-4][0-9]|[0-1][0-9]{2}|[1-9][0-9]|[0-9]))");
            Pattern DOMAIN_NAME = Pattern.compile("(([a-zA-Z0-9 -\ud7ff豈-﷏ﷰ-\uffef]([a-zA-Z0-9 -\ud7ff豈-﷏ﷰ-\uffef\\-]{0,61}[a-zA-Z0-9 -\ud7ff豈-﷏ﷰ-\uffef]){0,1}\\.)+[a-zA-Z -\ud7ff豈-﷏ﷰ-\uffef]{2,63}|" + IP_ADDRESS + SQLBuilder.PARENTHESES_RIGHT);
            WEB_URL = Pattern.compile("((?:(http|https|Http|Https):\\/\\/(?:(?:[a-zA-Z0-9\\$\\-\\_\\.\\+\\!\\*\\'\\(\\)\\,\\;\\?\\&\\=]|(?:\\%[a-fA-F0-9]{2})){1,64}(?:\\:(?:[a-zA-Z0-9\\$\\-\\_\\.\\+\\!\\*\\'\\(\\)\\,\\;\\?\\&\\=]|(?:\\%[a-fA-F0-9]{2})){1,25})?\\@)?)?(?:" + DOMAIN_NAME + ")(?:\\:\\d{1,5})?)(\\/(?:(?:[a-zA-Z0-9 -\ud7ff豈-﷏ﷰ-\uffef\\;\\/\\?\\:\\@\\&\\=\\#\\~\\-\\.\\+\\!\\*\\'\\(\\)\\,\\_])|(?:\\%[a-fA-F0-9]{2}))*)?(?:\\b|$)");
        } catch (Exception e) {
            FileLog.e(e);
        }
        leftBaseline = isTablet() ? 80 : 72;
        checkDisplaySize(ApplicationLoader.applicationContext, null);
        documentIcons = new int[]{mpEIGo.juqQQs.esbSDO.R.drawable.media_doc_blue, mpEIGo.juqQQs.esbSDO.R.drawable.media_doc_green, mpEIGo.juqQQs.esbSDO.R.drawable.media_doc_red, mpEIGo.juqQQs.esbSDO.R.drawable.media_doc_yellow};
        documentMediaIcons = new int[]{mpEIGo.juqQQs.esbSDO.R.drawable.media_doc_blue_b, mpEIGo.juqQQs.esbSDO.R.drawable.media_doc_green_b, mpEIGo.juqQQs.esbSDO.R.drawable.media_doc_red_b, mpEIGo.juqQQs.esbSDO.R.drawable.media_doc_yellow_b};
        hasCallPermissions = Build.VERSION.SDK_INT >= 23;
    }

    public static int getThumbForNameOrMime(String name, String mime, boolean media) {
        if (name == null || name.length() == 0) {
            return media ? documentMediaIcons[0] : documentIcons[0];
        }
        int color = -1;
        if (name.contains(".doc") || name.contains(".txt") || name.contains(".psd")) {
            color = 0;
        } else if (name.contains(".xls") || name.contains(".csv")) {
            color = 1;
        } else if (name.contains(".pdf") || name.contains(".ppt") || name.contains(".key")) {
            color = 2;
        } else if (name.contains(".zip") || name.contains(".rar") || name.contains(".ai") || name.contains(DefaultHlsExtractorFactory.MP3_FILE_EXTENSION) || name.contains(".mov") || name.contains(".avi")) {
            color = 3;
        }
        if (color == -1) {
            int idx = name.lastIndexOf(46);
            String ext = idx == -1 ? "" : name.substring(idx + 1);
            if (ext.length() != 0) {
                color = ext.charAt(0) % documentIcons.length;
            } else {
                color = name.charAt(0) % documentIcons.length;
            }
        }
        return media ? documentMediaIcons[color] : documentIcons[color];
    }

    public static int[] calcDrawableColor(Drawable drawable) {
        int[] colors;
        Bitmap b;
        int bitmapColor = -16777216;
        int[] result = new int[4];
        try {
            if (!(drawable instanceof BitmapDrawable)) {
                if (drawable instanceof ColorDrawable) {
                    bitmapColor = ((ColorDrawable) drawable).getColor();
                } else if ((drawable instanceof BackgroundGradientDrawable) && (colors = ((BackgroundGradientDrawable) drawable).getColorsList()) != null && colors.length > 0) {
                    bitmapColor = colors[0];
                }
            } else {
                Bitmap bitmap = ((BitmapDrawable) drawable).getBitmap();
                if (bitmap != null && (b = Bitmaps.createScaledBitmap(bitmap, 1, 1, true)) != null) {
                    bitmapColor = b.getPixel(0, 0);
                    if (bitmap != b) {
                        b.recycle();
                    }
                }
            }
        } catch (Exception e) {
            FileLog.e(e);
        }
        double[] hsv = rgbToHsv((bitmapColor >> 16) & 255, (bitmapColor >> 8) & 255, bitmapColor & 255);
        hsv[1] = Math.min(1.0d, hsv[1] + 0.05d + ((1.0d - hsv[1]) * 0.1d));
        double v = Math.max(FirebaseRemoteConfig.DEFAULT_VALUE_FOR_DOUBLE, hsv[2] * 0.65d);
        int[] rgb = hsvToRgb(hsv[0], hsv[1], v);
        result[0] = Color.argb(102, rgb[0], rgb[1], rgb[2]);
        result[1] = Color.argb(136, rgb[0], rgb[1], rgb[2]);
        double v2 = Math.max(FirebaseRemoteConfig.DEFAULT_VALUE_FOR_DOUBLE, hsv[2] * 0.72d);
        int[] rgb2 = hsvToRgb(hsv[0], hsv[1], v2);
        result[2] = Color.argb(102, rgb2[0], rgb2[1], rgb2[2]);
        result[3] = Color.argb(136, rgb2[0], rgb2[1], rgb2[2]);
        return result;
    }

    public static double[] rgbToHsv(int r, int g, int b) {
        double h;
        double h2;
        double rf = ((double) r) / 255.0d;
        double gf = ((double) g) / 255.0d;
        double bf = ((double) b) / 255.0d;
        double max = (rf <= gf || rf <= bf) ? gf > bf ? gf : bf : rf;
        double min = (rf >= gf || rf >= bf) ? gf < bf ? gf : bf : rf;
        double d = max - min;
        double s = FirebaseRemoteConfig.DEFAULT_VALUE_FOR_DOUBLE;
        if (max != FirebaseRemoteConfig.DEFAULT_VALUE_FOR_DOUBLE) {
            s = d / max;
        }
        if (max == min) {
            h2 = FirebaseRemoteConfig.DEFAULT_VALUE_FOR_DOUBLE;
        } else {
            if (rf > gf && rf > bf) {
                h = ((gf - bf) / d) + ((double) (gf < bf ? 6 : 0));
            } else if (gf > bf) {
                h = ((bf - rf) / d) + 2.0d;
            } else {
                h = ((rf - gf) / d) + 4.0d;
            }
            h2 = h / 6.0d;
        }
        return new double[]{h2, s, max};
    }

    private static int[] hsvToRgb(double h, double s, double v) {
        double r;
        double g = FirebaseRemoteConfig.DEFAULT_VALUE_FOR_DOUBLE;
        double b = FirebaseRemoteConfig.DEFAULT_VALUE_FOR_DOUBLE;
        double i = (int) Math.floor(h * 6.0d);
        double f = (6.0d * h) - i;
        double p = (1.0d - s) * v;
        double q = (1.0d - (f * s)) * v;
        double t = (1.0d - ((1.0d - f) * s)) * v;
        int i2 = ((int) i) % 6;
        if (i2 == 0) {
            r = v;
            g = t;
            b = p;
        } else if (i2 == 1) {
            r = q;
            g = v;
            b = p;
        } else if (i2 == 2) {
            r = p;
            g = v;
            b = t;
        } else if (i2 == 3) {
            r = p;
            g = q;
            b = v;
        } else if (i2 == 4) {
            r = t;
            g = p;
            b = v;
        } else if (i2 != 5) {
            r = 0.0d;
        } else {
            r = v;
            g = p;
            b = q;
        }
        return new int[]{(int) (r * 255.0d), (int) (g * 255.0d), (int) (b * 255.0d)};
    }

    public static void requestAdjustResize(Activity activity, int classGuid) {
        if (activity == null || isTablet()) {
            return;
        }
        activity.getWindow().setSoftInputMode(16);
        adjustOwnerClassGuid = classGuid;
    }

    public static void setAdjustResizeToNothing(Activity activity, int classGuid) {
        if (activity != null && !isTablet() && adjustOwnerClassGuid == classGuid) {
            activity.getWindow().setSoftInputMode(48);
        }
    }

    public static void removeAdjustResize(Activity activity, int classGuid) {
        if (activity != null && !isTablet() && adjustOwnerClassGuid == classGuid) {
            activity.getWindow().setSoftInputMode(32);
        }
    }

    public static boolean isGoogleMapsInstalled(final BaseFragment fragment) {
        try {
            ApplicationLoader.applicationContext.getPackageManager().getApplicationInfo("com.google.android.apps.maps", 0);
            return true;
        } catch (PackageManager.NameNotFoundException e) {
            if (fragment.getParentActivity() == null) {
                return false;
            }
            AlertDialog.Builder builder = new AlertDialog.Builder(fragment.getParentActivity());
            builder.setMessage(LocaleController.getString("InstallGoogleMaps", mpEIGo.juqQQs.esbSDO.R.string.InstallGoogleMaps));
            builder.setPositiveButton(LocaleController.getString("OK", mpEIGo.juqQQs.esbSDO.R.string.OK), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$AndroidUtilities$5yEu6PK1TWhEpQ5MeikobxOudfk
                @Override // android.content.DialogInterface.OnClickListener
                public final void onClick(DialogInterface dialogInterface, int i) {
                    AndroidUtilities.lambda$isGoogleMapsInstalled$0(fragment, dialogInterface, i);
                }
            });
            builder.setNegativeButton(LocaleController.getString("Cancel", mpEIGo.juqQQs.esbSDO.R.string.Cancel), null);
            fragment.showDialog(builder.create());
            return false;
        }
    }

    static /* synthetic */ void lambda$isGoogleMapsInstalled$0(BaseFragment fragment, DialogInterface dialogInterface, int i) {
        try {
            Intent intent = new Intent("android.intent.action.VIEW", Uri.parse("market://details?id=com.google.android.apps.maps"));
            fragment.getParentActivity().startActivityForResult(intent, SlidingItemMenuRecyclerView.DEFAULT_ITEM_SCROLL_DURATION);
        } catch (Exception e1) {
            FileLog.e(e1);
        }
    }

    public static int[] toIntArray(List<Integer> integers) {
        int[] ret = new int[integers.size()];
        for (int i = 0; i < ret.length; i++) {
            ret[i] = integers.get(i).intValue();
        }
        return ret;
    }

    public static boolean isInternalUri(Uri uri) {
        String path = uri.getPath();
        if (path == null) {
            return false;
        }
        if (path.matches(Pattern.quote(new File(ApplicationLoader.applicationContext.getCacheDir(), "voip_logs").getAbsolutePath()) + "/\\d+\\.log")) {
            return false;
        }
        int tries = 0;
        do {
            if (path != null && path.length() > 4096) {
                return true;
            }
            try {
                String str = Utilities.readlink(path);
                if (str != null && !str.equals(path)) {
                    path = str;
                    tries++;
                } else {
                    if (path != null) {
                        try {
                            String path2 = new File(path).getCanonicalPath();
                            if (path2 != null) {
                                path = path2;
                            }
                        } catch (Exception e) {
                            path.replace("/./", "/");
                        }
                    }
                    if (path.endsWith(".attheme") || path == null) {
                        return false;
                    }
                    String lowerCase = path.toLowerCase();
                    StringBuilder sb = new StringBuilder();
                    sb.append("/data/data/");
                    sb.append(ApplicationLoader.applicationContext.getPackageName());
                    return lowerCase.contains(sb.toString());
                }
            } catch (Throwable th) {
                return true;
            }
        } while (tries < 10);
        return true;
    }

    public static void lockOrientation(Activity activity) {
        if (activity == null || prevOrientation != -10) {
            return;
        }
        try {
            prevOrientation = activity.getRequestedOrientation();
            WindowManager manager = (WindowManager) activity.getSystemService("window");
            if (manager != null && manager.getDefaultDisplay() != null) {
                int rotation = manager.getDefaultDisplay().getRotation();
                int orientation = activity.getResources().getConfiguration().orientation;
                if (rotation == 3) {
                    if (orientation == 1) {
                        activity.setRequestedOrientation(1);
                    } else {
                        activity.setRequestedOrientation(8);
                    }
                } else if (rotation == 1) {
                    if (orientation == 1) {
                        activity.setRequestedOrientation(9);
                    } else {
                        activity.setRequestedOrientation(0);
                    }
                } else if (rotation == 0) {
                    if (orientation == 2) {
                        activity.setRequestedOrientation(0);
                    } else {
                        activity.setRequestedOrientation(1);
                    }
                } else if (orientation == 2) {
                    activity.setRequestedOrientation(8);
                } else {
                    activity.setRequestedOrientation(9);
                }
            }
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    public static void unlockOrientation(Activity activity) {
        if (activity == null) {
            return;
        }
        try {
            if (prevOrientation != -10) {
                activity.setRequestedOrientation(prevOrientation);
                prevOrientation = -10;
            }
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    private static class VcardData {
        String name;
        ArrayList<String> phones;
        StringBuilder vcard;

        private VcardData() {
            this.phones = new ArrayList<>();
            this.vcard = new StringBuilder();
        }
    }

    public static class VcardItem {
        public int type;
        public ArrayList<String> vcardData = new ArrayList<>();
        public String fullData = "";
        public boolean checked = true;

        public String[] getRawValue() {
            byte[] bytes;
            int idx = this.fullData.indexOf(58);
            if (idx >= 0) {
                String valueType = this.fullData.substring(0, idx);
                String value = this.fullData.substring(idx + 1);
                String nameEncoding = null;
                String nameCharset = "UTF-8";
                String[] params = valueType.split(";");
                for (String str : params) {
                    String[] args2 = str.split("=");
                    if (args2.length == 2) {
                        if (args2[0].equals("CHARSET")) {
                            nameCharset = args2[1];
                        } else if (args2[0].equals("ENCODING")) {
                            nameEncoding = args2[1];
                        }
                    }
                }
                String[] args = value.split(";");
                for (int a = 0; a < args.length; a++) {
                    if (!TextUtils.isEmpty(args[a]) && nameEncoding != null && nameEncoding.equalsIgnoreCase("QUOTED-PRINTABLE") && (bytes = AndroidUtilities.decodeQuotedPrintable(AndroidUtilities.getStringBytes(args[a]))) != null && bytes.length != 0) {
                        try {
                            args[a] = new String(bytes, nameCharset);
                        } catch (Exception e) {
                        }
                    }
                }
                return args;
            }
            return new String[0];
        }

        public String getValue(boolean format) {
            byte[] bytes;
            StringBuilder result = new StringBuilder();
            int idx = this.fullData.indexOf(58);
            if (idx < 0) {
                return "";
            }
            if (result.length() > 0) {
                result.append(", ");
            }
            String valueType = this.fullData.substring(0, idx);
            String value = this.fullData.substring(idx + 1);
            String[] params = valueType.split(";");
            String nameEncoding = null;
            String nameCharset = "UTF-8";
            for (String str : params) {
                String[] args2 = str.split("=");
                if (args2.length == 2) {
                    if (args2[0].equals("CHARSET")) {
                        nameCharset = args2[1];
                    } else if (args2[0].equals("ENCODING")) {
                        nameEncoding = args2[1];
                    }
                }
            }
            String[] args = value.split(";");
            boolean added = false;
            for (int a = 0; a < args.length; a++) {
                if (!TextUtils.isEmpty(args[a])) {
                    if (nameEncoding != null && nameEncoding.equalsIgnoreCase("QUOTED-PRINTABLE") && (bytes = AndroidUtilities.decodeQuotedPrintable(AndroidUtilities.getStringBytes(args[a]))) != null && bytes.length != 0) {
                        try {
                            args[a] = new String(bytes, nameCharset);
                        } catch (Exception e) {
                        }
                    }
                    if (added && result.length() > 0) {
                        result.append(" ");
                    }
                    result.append(args[a]);
                    if (!added) {
                        added = args[a].length() > 0;
                    }
                }
            }
            if (format) {
                int i = this.type;
                if (i == 0) {
                    return PhoneFormat.getInstance().format(result.toString());
                }
                if (i == 5) {
                    String[] date = result.toString().split(ExifInterface.GPS_DIRECTION_TRUE);
                    if (date.length > 0) {
                        String[] date2 = date[0].split("-");
                        if (date2.length == 3) {
                            Calendar calendar = Calendar.getInstance();
                            calendar.set(1, Utilities.parseInt(date2[0]).intValue());
                            calendar.set(2, Utilities.parseInt(date2[1]).intValue() - 1);
                            calendar.set(5, Utilities.parseInt(date2[2]).intValue());
                            return LocaleController.getInstance().formatterYearMax.format(calendar.getTime());
                        }
                    }
                }
            }
            return result.toString();
        }

        public String getRawType(boolean first) {
            int idx = this.fullData.indexOf(58);
            if (idx < 0) {
                return "";
            }
            String value = this.fullData.substring(0, idx);
            if (this.type == 20) {
                String[] args = value.substring(2).split(";");
                if (first) {
                    return args[0];
                }
                if (args.length > 1) {
                    return args[args.length - 1];
                }
                return "";
            }
            String[] args2 = value.split(";");
            for (int a = 0; a < args2.length; a++) {
                if (args2[a].indexOf(61) < 0) {
                    value = args2[a];
                }
            }
            return value;
        }

        /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue */
        public String getType() {
            String value;
            int i = this.type;
            if (i == 5) {
                return LocaleController.getString("ContactBirthday", mpEIGo.juqQQs.esbSDO.R.string.ContactBirthday);
            }
            if (i == 6) {
                if ("ORG".equalsIgnoreCase(getRawType(true))) {
                    return LocaleController.getString("ContactJob", mpEIGo.juqQQs.esbSDO.R.string.ContactJob);
                }
                return LocaleController.getString("ContactJobTitle", mpEIGo.juqQQs.esbSDO.R.string.ContactJobTitle);
            }
            int idx = this.fullData.indexOf(58);
            if (idx < 0) {
                return "";
            }
            String value2 = this.fullData.substring(0, idx);
            if (this.type == 20) {
                value = value2.substring(2).split(";")[0];
            } else {
                String[] args = value2.split(";");
                for (int a = 0; a < args.length; a++) {
                    if (args[a].indexOf(61) < 0) {
                        value2 = args[a];
                    }
                }
                if (value2.startsWith("X-")) {
                    value2 = value2.substring(2);
                }
                byte b = -1;
                switch (value2.hashCode()) {
                    case -2015525726:
                        if (value2.equals("MOBILE")) {
                            b = 2;
                        }
                        break;
                    case 2064738:
                        if (value2.equals("CELL")) {
                            b = 3;
                        }
                        break;
                    case 2223327:
                        if (value2.equals("HOME")) {
                            b = 1;
                        }
                        break;
                    case 2464291:
                        if (value2.equals("PREF")) {
                            b = 0;
                        }
                        break;
                    case 2670353:
                        if (value2.equals("WORK")) {
                            b = 5;
                        }
                        break;
                    case 75532016:
                        if (value2.equals("OTHER")) {
                            b = 4;
                        }
                        break;
                }
                if (b == 0) {
                    value = LocaleController.getString("PhoneMain", mpEIGo.juqQQs.esbSDO.R.string.PhoneMain);
                } else if (b == 1) {
                    value = LocaleController.getString("PhoneHome", mpEIGo.juqQQs.esbSDO.R.string.PhoneHome);
                } else if (b == 2 || b == 3) {
                    value = LocaleController.getString("PhoneMobile", mpEIGo.juqQQs.esbSDO.R.string.PhoneMobile);
                } else if (b == 4) {
                    value = LocaleController.getString("PhoneOther", mpEIGo.juqQQs.esbSDO.R.string.PhoneOther);
                } else {
                    value = b != 5 ? value2 : LocaleController.getString("PhoneWork", mpEIGo.juqQQs.esbSDO.R.string.PhoneWork);
                }
            }
            return value.substring(0, 1).toUpperCase() + value.substring(1).toLowerCase();
        }
    }

    public static byte[] getStringBytes(String src) {
        try {
            return src.getBytes("UTF-8");
        } catch (Exception e) {
            return new byte[0];
        }
    }

    /* JADX WARN: Can't wrap try/catch for region: R(13:0|2|(3:180|4|5)(2:182|8)|9|(6:10|(3:12|(3:186|14|193)(9:185|15|16|(4:18|178|19|(3:21|22|23)(3:24|(3:28|(1:30)(2:31|(1:33)(2:34|(1:68)(2:41|(1:43)(2:44|(1:46)(2:47|(1:49)(2:50|(1:(1:67))(2:57|(1:59)(2:60|(1:62)(2:63|(1:65))))))))))|(1:72))|73))|(1:(3:79|(1:81)|82)(1:83))|(2:85|86)|87|88|(8:188|(1:96)|97|(3:99|175|100)(1:101)|102|(1:105)(2:106|(5:117|(3:119|(2:122|(2:124|197)(2:125|(2:127|195)(1:198)))(2:121|196)|128)|194|129|(1:137))(2:113|(1:115)(1:116)))|141|191)(3:189|92|192))|190)(1:184)|145|146|173|174)|142|176|143|149|(4:152|(2:168|200)(5:(1:157)|158|(2:159|(2:161|(2:203|163)(1:164))(2:202|165))|166|201)|169|150)|199|170|174) */
    /* JADX WARN: Code restructure failed: missing block: B:147:0x02ea, code lost:
    
        r0 = move-exception;
     */
    /* JADX WARN: Code restructure failed: missing block: B:148:0x02eb, code lost:
    
        im.uwrkaxlmjj.messenger.FileLog.e(r0);
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static java.util.ArrayList<im.uwrkaxlmjj.tgnet.TLRPC.User> loadVCardFromStream(android.net.Uri r26, int r27, boolean r28, java.util.ArrayList<im.uwrkaxlmjj.messenger.AndroidUtilities.VcardItem> r29, java.lang.String r30) {
        /*
            Method dump skipped, instruction units count: 916
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.AndroidUtilities.loadVCardFromStream(android.net.Uri, int, boolean, java.util.ArrayList, java.lang.String):java.util.ArrayList");
    }

    public static Typeface getTypeface(String assetPath) {
        Typeface t;
        Typeface typeface;
        synchronized (typefaceCache) {
            if (!typefaceCache.containsKey(assetPath)) {
                try {
                    if (Build.VERSION.SDK_INT >= 26) {
                        Typeface.Builder builder = new Typeface.Builder(ApplicationLoader.applicationContext.getAssets(), assetPath);
                        if (assetPath.contains("medium")) {
                            builder.setWeight(HardwareConfigState.DEFAULT_MAXIMUM_FDS_FOR_HARDWARE_CONFIGS);
                        }
                        if (assetPath.contains(TtmlNode.ITALIC)) {
                            builder.setItalic(true);
                        }
                        t = builder.build();
                    } else {
                        t = Typeface.createFromAsset(ApplicationLoader.applicationContext.getAssets(), assetPath);
                    }
                    typefaceCache.put(assetPath, t);
                } catch (Exception e) {
                    if (BuildVars.LOGS_ENABLED) {
                        FileLog.e("Could not get typeface '" + assetPath + "' because " + e.getMessage());
                    }
                    return null;
                }
            }
            typeface = typefaceCache.get(assetPath);
        }
        return typeface;
    }

    public static boolean isWaitingForSms() {
        boolean value;
        synchronized (smsLock) {
            value = waitingForSms;
        }
        return value;
    }

    public static void setWaitingForSms(boolean value) {
        synchronized (smsLock) {
            waitingForSms = value;
            if (value) {
                try {
                    SmsRetrieverClient client = SmsRetriever.getClient(ApplicationLoader.applicationContext);
                    Task<Void> task = client.startSmsRetriever();
                    task.addOnSuccessListener(new OnSuccessListener() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$AndroidUtilities$6dLIn-yUEv55yfGHqbOy_tRdOHw
                        @Override // com.google.android.gms.tasks.OnSuccessListener
                        public final void onSuccess(Object obj) {
                            AndroidUtilities.lambda$setWaitingForSms$1((Void) obj);
                        }
                    });
                } catch (Throwable e) {
                    FileLog.e(e);
                }
            }
        }
    }

    static /* synthetic */ void lambda$setWaitingForSms$1(Void aVoid) {
        if (BuildVars.DEBUG_VERSION) {
            FileLog.d("sms listener registered");
        }
    }

    public static int getShadowHeight() {
        float f = density;
        if (f >= 4.0f) {
            return 3;
        }
        if (f >= 2.0f) {
            return 2;
        }
        return 1;
    }

    public static boolean isWaitingForCall() {
        boolean value;
        synchronized (callLock) {
            value = waitingForCall;
        }
        return value;
    }

    public static void setWaitingForCall(boolean value) {
        synchronized (callLock) {
            waitingForCall = value;
        }
    }

    public static boolean showKeyboard(View view) {
        if (view == null) {
            return false;
        }
        try {
            InputMethodManager inputManager = (InputMethodManager) view.getContext().getSystemService("input_method");
            return inputManager.showSoftInput(view, 1);
        } catch (Exception e) {
            FileLog.e(e);
            return false;
        }
    }

    public static boolean isKeyboardShowed(View view) {
        if (view == null) {
            return false;
        }
        try {
            InputMethodManager inputManager = (InputMethodManager) view.getContext().getSystemService("input_method");
            return inputManager.isActive(view);
        } catch (Exception e) {
            FileLog.e(e);
            return false;
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:28:0x0079 A[Catch: Exception -> 0x00a6, TryCatch #0 {Exception -> 0x00a6, blocks: (B:3:0x0002, B:5:0x0015, B:7:0x0019, B:8:0x001e, B:10:0x0024, B:19:0x0045, B:21:0x0051, B:23:0x0068, B:24:0x006d, B:26:0x0073, B:32:0x0082, B:34:0x0088, B:36:0x0094, B:28:0x0079, B:38:0x009d, B:11:0x002a, B:13:0x0031, B:15:0x0035, B:16:0x003a, B:18:0x0040), top: B:43:0x0002 }] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static java.lang.String[] getCurrentKeyboardLanguage() {
        /*
            java.lang.String r0 = "en"
            android.content.Context r1 = im.uwrkaxlmjj.messenger.ApplicationLoader.applicationContext     // Catch: java.lang.Exception -> La6
            java.lang.String r2 = "input_method"
            java.lang.Object r1 = r1.getSystemService(r2)     // Catch: java.lang.Exception -> La6
            android.view.inputmethod.InputMethodManager r1 = (android.view.inputmethod.InputMethodManager) r1     // Catch: java.lang.Exception -> La6
            android.view.inputmethod.InputMethodSubtype r2 = r1.getCurrentInputMethodSubtype()     // Catch: java.lang.Exception -> La6
            r3 = 0
            r4 = 24
            if (r2 == 0) goto L2a
            int r5 = android.os.Build.VERSION.SDK_INT     // Catch: java.lang.Exception -> La6
            if (r5 < r4) goto L1e
            java.lang.String r4 = r2.getLanguageTag()     // Catch: java.lang.Exception -> La6
            r3 = r4
        L1e:
            boolean r4 = android.text.TextUtils.isEmpty(r3)     // Catch: java.lang.Exception -> La6
            if (r4 == 0) goto L45
            java.lang.String r4 = r2.getLocale()     // Catch: java.lang.Exception -> La6
            r3 = r4
            goto L45
        L2a:
            android.view.inputmethod.InputMethodSubtype r5 = r1.getLastInputMethodSubtype()     // Catch: java.lang.Exception -> La6
            r2 = r5
            if (r2 == 0) goto L45
            int r5 = android.os.Build.VERSION.SDK_INT     // Catch: java.lang.Exception -> La6
            if (r5 < r4) goto L3a
            java.lang.String r4 = r2.getLanguageTag()     // Catch: java.lang.Exception -> La6
            r3 = r4
        L3a:
            boolean r4 = android.text.TextUtils.isEmpty(r3)     // Catch: java.lang.Exception -> La6
            if (r4 == 0) goto L45
            java.lang.String r4 = r2.getLocale()     // Catch: java.lang.Exception -> La6
            r3 = r4
        L45:
            boolean r4 = android.text.TextUtils.isEmpty(r3)     // Catch: java.lang.Exception -> La6
            r5 = 45
            r6 = 95
            r7 = 0
            r8 = 1
            if (r4 == 0) goto L9d
            java.lang.String r4 = im.uwrkaxlmjj.messenger.LocaleController.getSystemLocaleStringIso639()     // Catch: java.lang.Exception -> La6
            r3 = r4
            im.uwrkaxlmjj.messenger.LocaleController r4 = im.uwrkaxlmjj.messenger.LocaleController.getInstance()     // Catch: java.lang.Exception -> La6
            im.uwrkaxlmjj.messenger.LocaleController$LocaleInfo r4 = r4.getCurrentLocaleInfo()     // Catch: java.lang.Exception -> La6
            java.lang.String r9 = r4.getBaseLangCode()     // Catch: java.lang.Exception -> La6
            boolean r10 = android.text.TextUtils.isEmpty(r9)     // Catch: java.lang.Exception -> La6
            if (r10 == 0) goto L6d
            java.lang.String r10 = r4.getLangCode()     // Catch: java.lang.Exception -> La6
            r9 = r10
        L6d:
            boolean r10 = r3.contains(r9)     // Catch: java.lang.Exception -> La6
            if (r10 != 0) goto L79
            boolean r10 = r9.contains(r3)     // Catch: java.lang.Exception -> La6
            if (r10 == 0) goto L82
        L79:
            boolean r10 = r3.contains(r0)     // Catch: java.lang.Exception -> La6
            if (r10 != 0) goto L81
            r9 = r0
            goto L82
        L81:
            r9 = 0
        L82:
            boolean r10 = android.text.TextUtils.isEmpty(r9)     // Catch: java.lang.Exception -> La6
            if (r10 != 0) goto L94
            r10 = 2
            java.lang.String[] r10 = new java.lang.String[r10]     // Catch: java.lang.Exception -> La6
            java.lang.String r5 = r3.replace(r6, r5)     // Catch: java.lang.Exception -> La6
            r10[r7] = r5     // Catch: java.lang.Exception -> La6
            r10[r8] = r9     // Catch: java.lang.Exception -> La6
            return r10
        L94:
            java.lang.String[] r8 = new java.lang.String[r8]     // Catch: java.lang.Exception -> La6
            java.lang.String r5 = r3.replace(r6, r5)     // Catch: java.lang.Exception -> La6
            r8[r7] = r5     // Catch: java.lang.Exception -> La6
            return r8
        L9d:
            java.lang.String[] r4 = new java.lang.String[r8]     // Catch: java.lang.Exception -> La6
            java.lang.String r5 = r3.replace(r6, r5)     // Catch: java.lang.Exception -> La6
            r4[r7] = r5     // Catch: java.lang.Exception -> La6
            return r4
        La6:
            r1 = move-exception
            java.lang.String[] r0 = new java.lang.String[]{r0}
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.AndroidUtilities.getCurrentKeyboardLanguage():java.lang.String[]");
    }

    public static void hideKeyboard(View view) {
        if (view == null) {
            return;
        }
        try {
            InputMethodManager imm = (InputMethodManager) view.getContext().getSystemService("input_method");
            if (!imm.isActive()) {
                return;
            }
            imm.hideSoftInputFromWindow(view.getWindowToken(), 0);
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    public static File getCacheDir() {
        String state = null;
        try {
            state = Environment.getExternalStorageState();
        } catch (Exception e) {
            FileLog.e(e);
        }
        if (state == null || state.startsWith("mounted")) {
            try {
                File file = ApplicationLoader.applicationContext.getExternalCacheDir();
                if (file != null) {
                    return file;
                }
            } catch (Exception e2) {
                FileLog.e(e2);
            }
        }
        try {
            File file2 = ApplicationLoader.applicationContext.getCacheDir();
            if (file2 != null) {
                return file2;
            }
        } catch (Exception e3) {
            FileLog.e(e3);
        }
        return new File("");
    }

    public static int dp(float value) {
        if (value == 0.0f) {
            return 0;
        }
        return (int) Math.ceil(density * value);
    }

    public static int dpr(float value) {
        if (value == 0.0f) {
            return 0;
        }
        return Math.round(density * value);
    }

    public static int dp2(float value) {
        if (value == 0.0f) {
            return 0;
        }
        return (int) Math.floor(density * value);
    }

    public static int compare(int lhs, int rhs) {
        if (lhs == rhs) {
            return 0;
        }
        if (lhs > rhs) {
            return 1;
        }
        return -1;
    }

    public static float dpf2(float value) {
        if (value == 0.0f) {
            return 0.0f;
        }
        return density * value;
    }

    public static float sp2px(float spValue) {
        if (spValue == 0.0f || ApplicationLoader.applicationContext == null) {
            return 0.0f;
        }
        return (ApplicationLoader.applicationContext.getResources().getDisplayMetrics().scaledDensity * spValue) + 0.5f;
    }

    public static void checkDisplaySize(Context context, Configuration newConfiguration) {
        Display display;
        try {
            int oldDensity = (int) density;
            float f = context.getResources().getDisplayMetrics().density;
            density = f;
            int newDensity = (int) f;
            if (firstConfigurationWas && oldDensity != newDensity) {
                Theme.reloadAllResources(context);
            }
            boolean z = true;
            firstConfigurationWas = true;
            Configuration configuration = newConfiguration;
            if (configuration == null) {
                configuration = context.getResources().getConfiguration();
            }
            if (configuration.keyboard == 1 || configuration.hardKeyboardHidden != 1) {
                z = false;
            }
            usingHardwareInput = z;
            WindowManager manager = (WindowManager) context.getSystemService("window");
            if (manager != null && (display = manager.getDefaultDisplay()) != null) {
                display.getMetrics(displayMetrics);
                display.getSize(displaySize);
            }
            if (configuration.screenWidthDp != 0) {
                int newSize = (int) Math.ceil(configuration.screenWidthDp * density);
                if (Math.abs(displaySize.x - newSize) > 3) {
                    displaySize.x = newSize;
                }
            }
            int newSize2 = configuration.screenHeightDp;
            if (newSize2 != 0) {
                int newSize3 = (int) Math.ceil(configuration.screenHeightDp * density);
                if (Math.abs(displaySize.y - newSize3) > 3) {
                    displaySize.y = newSize3;
                }
            }
            int newSize4 = roundMessageSize;
            if (newSize4 == 0) {
                if (isTablet()) {
                    roundMessageSize = (int) (getMinTabletSide() * 0.6f);
                } else {
                    roundMessageSize = (int) (Math.min(displaySize.x, displaySize.y) * 0.6f);
                }
            }
            if (BuildVars.LOGS_ENABLED) {
                FileLog.e("display size = " + displaySize.x + " " + displaySize.y + " " + displayMetrics.xdpi + "x" + displayMetrics.ydpi);
            }
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    public static double fixLocationCoord(double value) {
        return ((long) (value * 1000000.0d)) / 1000000.0d;
    }

    public static float getPixelsInCM(float cm, boolean isX) {
        float f = cm / 2.54f;
        DisplayMetrics displayMetrics2 = displayMetrics;
        return f * (isX ? displayMetrics2.xdpi : displayMetrics2.ydpi);
    }

    public static int getMyLayerVersion(int layer) {
        return 65535 & layer;
    }

    public static int getPeerLayerVersion(int layer) {
        return (layer >> 16) & 65535;
    }

    public static int setMyLayerVersion(int layer, int version) {
        return ((-65536) & layer) | version;
    }

    public static int setPeerLayerVersion(int layer, int version) {
        return (65535 & layer) | (version << 16);
    }

    public static void runOnUIThread(Runnable runnable) {
        runOnUIThread(runnable, 0L);
    }

    public static void runOnUIThread(Runnable runnable, long delay) {
        if (delay == 0) {
            ApplicationLoader.applicationHandler.post(runnable);
        } else {
            ApplicationLoader.applicationHandler.postDelayed(runnable, delay);
        }
    }

    public static void cancelRunOnUIThread(Runnable runnable) {
        ApplicationLoader.applicationHandler.removeCallbacks(runnable);
    }

    public static boolean isTablet() {
        if (isTablet == null) {
            isTablet = Boolean.valueOf(ApplicationLoader.applicationContext.getResources().getBoolean(mpEIGo.juqQQs.esbSDO.R.bool.isTablet));
        }
        return isTablet.booleanValue();
    }

    public static boolean isSmallTablet() {
        float minSide = Math.min(displaySize.x, displaySize.y) / density;
        return minSide <= 700.0f;
    }

    public static int getMinTabletSide() {
        if (!isSmallTablet()) {
            int smallSide = Math.min(displaySize.x, displaySize.y);
            int leftSide = (smallSide * 35) / 100;
            if (leftSide < dp(320.0f)) {
                leftSide = dp(320.0f);
            }
            return smallSide - leftSide;
        }
        int smallSide2 = Math.min(displaySize.x, displaySize.y);
        int maxSide = Math.max(displaySize.x, displaySize.y);
        int leftSide2 = (maxSide * 35) / 100;
        if (leftSide2 < dp(320.0f)) {
            leftSide2 = dp(320.0f);
        }
        return Math.min(smallSide2, maxSide - leftSide2);
    }

    public static int getPhotoSize() {
        if (photoSize == null) {
            photoSize = 1280;
        }
        return photoSize.intValue();
    }

    public static void endIncomingCall() {
        if (!hasCallPermissions) {
            return;
        }
        try {
            TelephonyManager tm = (TelephonyManager) ApplicationLoader.applicationContext.getSystemService("phone");
            Method m = Class.forName(tm.getClass().getName()).getDeclaredMethod("getITelephony", new Class[0]);
            m.setAccessible(true);
            ITelephony telephonyService = (ITelephony) m.invoke(tm, new Object[0]);
            telephonyService.silenceRinger();
            telephonyService.endCall();
        } catch (Throwable e) {
            FileLog.e(e);
        }
    }

    public static String obtainLoginPhoneCall(String pattern) {
        if (!hasCallPermissions) {
            return null;
        }
        try {
            Cursor cursor = ApplicationLoader.applicationContext.getContentResolver().query(CallLog.Calls.CONTENT_URI, new String[]{"number", "date"}, "type IN (3,1,5)", null, "date DESC LIMIT 5");
            while (cursor.moveToNext()) {
                try {
                    String number = cursor.getString(0);
                    long date = cursor.getLong(1);
                    if (BuildVars.LOGS_ENABLED) {
                        FileLog.e("number = " + number);
                    }
                    if (Math.abs(System.currentTimeMillis() - date) < 3600000 && checkPhonePattern(pattern, number)) {
                        if (cursor != null) {
                            cursor.close();
                        }
                        return number;
                    }
                } finally {
                }
            }
            if (cursor != null) {
                cursor.close();
            }
        } catch (Exception e) {
            FileLog.e(e);
        }
        return null;
    }

    public static boolean checkPhonePattern(String pattern, String phone) {
        if (TextUtils.isEmpty(pattern) || pattern.equals("*")) {
            return true;
        }
        String[] args = pattern.split("\\*");
        String phone2 = PhoneFormat.stripExceptNumbers(phone);
        int checkStart = 0;
        for (String arg : args) {
            if (!TextUtils.isEmpty(arg)) {
                int index = phone2.indexOf(arg, checkStart);
                if (index == -1) {
                    return false;
                }
                checkStart = arg.length() + index;
            }
        }
        return true;
    }

    public static int getViewInset(View view) {
        return 0;
    }

    public static Point getRealScreenSize() {
        Point size = new Point();
        try {
            WindowManager windowManager = (WindowManager) ApplicationLoader.applicationContext.getSystemService("window");
            if (Build.VERSION.SDK_INT >= 17) {
                windowManager.getDefaultDisplay().getRealSize(size);
            } else {
                try {
                    Method mGetRawW = Display.class.getMethod("getRawWidth", new Class[0]);
                    Method mGetRawH = Display.class.getMethod("getRawHeight", new Class[0]);
                    size.set(((Integer) mGetRawW.invoke(windowManager.getDefaultDisplay(), new Object[0])).intValue(), ((Integer) mGetRawH.invoke(windowManager.getDefaultDisplay(), new Object[0])).intValue());
                } catch (Exception e) {
                    size.set(windowManager.getDefaultDisplay().getWidth(), windowManager.getDefaultDisplay().getHeight());
                    FileLog.e(e);
                }
            }
        } catch (Exception e2) {
            FileLog.e(e2);
        }
        return size;
    }

    public static void setEnabled(View view, boolean enabled) {
        if (view == null) {
            return;
        }
        view.setEnabled(enabled);
        if (view instanceof ViewGroup) {
            ViewGroup viewGroup = (ViewGroup) view;
            for (int i = 0; i < viewGroup.getChildCount(); i++) {
                setEnabled(viewGroup.getChildAt(i), enabled);
            }
        }
    }

    public static CharSequence getTrimmedString(CharSequence src) {
        if (src == null || src.length() == 0) {
            return src;
        }
        while (src.length() > 0 && (src.charAt(0) == '\n' || src.charAt(0) == ' ')) {
            src = src.subSequence(1, src.length());
        }
        while (src.length() > 0 && (src.charAt(src.length() - 1) == '\n' || src.charAt(src.length() - 1) == ' ')) {
            src = src.subSequence(0, src.length() - 1);
        }
        return src;
    }

    public static void setViewPagerEdgeEffectColor(ViewPager viewPager, int color) {
        if (Build.VERSION.SDK_INT >= 21) {
            try {
                Field field = ViewPager.class.getDeclaredField("mLeftEdge");
                field.setAccessible(true);
                EdgeEffect mLeftEdge = (EdgeEffect) field.get(viewPager);
                if (mLeftEdge != null) {
                    mLeftEdge.setColor(color);
                }
                Field field2 = ViewPager.class.getDeclaredField("mRightEdge");
                field2.setAccessible(true);
                EdgeEffect mRightEdge = (EdgeEffect) field2.get(viewPager);
                if (mRightEdge != null) {
                    mRightEdge.setColor(color);
                }
            } catch (Exception e) {
            }
        }
    }

    public static void setScrollViewEdgeEffectColor(HorizontalScrollView scrollView, int color) {
        if (Build.VERSION.SDK_INT >= 21) {
            try {
                Field field = HorizontalScrollView.class.getDeclaredField("mEdgeGlowLeft");
                field.setAccessible(true);
                EdgeEffect mEdgeGlowTop = (EdgeEffect) field.get(scrollView);
                if (mEdgeGlowTop != null) {
                    mEdgeGlowTop.setColor(color);
                }
                Field field2 = HorizontalScrollView.class.getDeclaredField("mEdgeGlowRight");
                field2.setAccessible(true);
                EdgeEffect mEdgeGlowBottom = (EdgeEffect) field2.get(scrollView);
                if (mEdgeGlowBottom != null) {
                    mEdgeGlowBottom.setColor(color);
                }
            } catch (Exception e) {
                FileLog.e(e);
            }
        }
    }

    public static void setScrollViewEdgeEffectColor(ScrollView scrollView, int color) {
    }

    public static void clearDrawableAnimation(View view) {
        if (Build.VERSION.SDK_INT < 21 || view == null) {
            return;
        }
        if (view instanceof ListView) {
            Drawable drawable = ((ListView) view).getSelector();
            if (drawable != null) {
                drawable.setState(StateSet.NOTHING);
                return;
            }
            return;
        }
        Drawable drawable2 = view.getBackground();
        if (drawable2 != null) {
            drawable2.setState(StateSet.NOTHING);
            drawable2.jumpToCurrentState();
        }
    }

    public static SpannableStringBuilder replaceTags(String str) {
        return replaceTags(str, 11, new Object[0]);
    }

    public static SpannableStringBuilder replaceTags(String str, int flag, Object... args) {
        try {
            StringBuilder stringBuilder = new StringBuilder(str);
            if ((flag & 1) != 0) {
                while (true) {
                    int start = stringBuilder.indexOf("<br>");
                    if (start == -1) {
                        break;
                    }
                    stringBuilder.replace(start, start + 4, ShellAdbUtils.COMMAND_LINE_END);
                }
                while (true) {
                    int start2 = stringBuilder.indexOf("<br/>");
                    if (start2 == -1) {
                        break;
                    }
                    stringBuilder.replace(start2, start2 + 5, ShellAdbUtils.COMMAND_LINE_END);
                }
            }
            ArrayList<Integer> bolds = new ArrayList<>();
            if ((flag & 2) != 0) {
                while (true) {
                    int start3 = stringBuilder.indexOf("<b>");
                    if (start3 == -1) {
                        break;
                    }
                    stringBuilder.replace(start3, start3 + 3, "");
                    int end = stringBuilder.indexOf("</b>");
                    if (end == -1) {
                        end = stringBuilder.indexOf("<b>");
                    }
                    stringBuilder.replace(end, end + 4, "");
                    bolds.add(Integer.valueOf(start3));
                    bolds.add(Integer.valueOf(end));
                }
                while (true) {
                    int start4 = stringBuilder.indexOf("**");
                    if (start4 == -1) {
                        break;
                    }
                    stringBuilder.replace(start4, start4 + 2, "");
                    int end2 = stringBuilder.indexOf("**");
                    if (end2 >= 0) {
                        stringBuilder.replace(end2, end2 + 2, "");
                        bolds.add(Integer.valueOf(start4));
                        bolds.add(Integer.valueOf(end2));
                    }
                }
            }
            if ((flag & 8) != 0) {
                while (true) {
                    int start5 = stringBuilder.indexOf("**");
                    if (start5 == -1) {
                        break;
                    }
                    stringBuilder.replace(start5, start5 + 2, "");
                    int end3 = stringBuilder.indexOf("**");
                    if (end3 >= 0) {
                        stringBuilder.replace(end3, end3 + 2, "");
                        bolds.add(Integer.valueOf(start5));
                        bolds.add(Integer.valueOf(end3));
                    }
                }
            }
            SpannableStringBuilder spannableStringBuilder = new SpannableStringBuilder(stringBuilder);
            for (int a = 0; a < bolds.size() / 2; a++) {
                spannableStringBuilder.setSpan(new TypefaceSpan(getTypeface("fonts/rmedium.ttf")), bolds.get(a * 2).intValue(), bolds.get((a * 2) + 1).intValue(), 33);
            }
            return spannableStringBuilder;
        } catch (Exception e) {
            FileLog.e(e);
            return new SpannableStringBuilder(str);
        }
    }

    public static class LinkMovementMethodMy extends LinkMovementMethod {
        @Override // android.text.method.LinkMovementMethod, android.text.method.ScrollingMovementMethod, android.text.method.BaseMovementMethod, android.text.method.MovementMethod
        public boolean onTouchEvent(TextView widget, Spannable buffer, MotionEvent event) {
            try {
                boolean result = super.onTouchEvent(widget, buffer, event);
                if (event.getAction() == 1 || event.getAction() == 3) {
                    Selection.removeSelection(buffer);
                }
                return result;
            } catch (Exception e) {
                FileLog.e(e);
                return false;
            }
        }
    }

    public static boolean needShowPasscode() {
        return needShowPasscode(false);
    }

    public static boolean needShowPasscode(boolean reset) {
        boolean wasInBackground = ForegroundDetector.getInstance().isWasInBackground(reset);
        if (reset) {
            ForegroundDetector.getInstance().resetBackgroundVar();
        }
        return SharedConfig.passcodeHash.length() > 0 && wasInBackground && (SharedConfig.appLocked || (!(SharedConfig.autoLockIn == 0 || SharedConfig.lastPauseTime == 0 || SharedConfig.appLocked || SharedConfig.lastPauseTime + SharedConfig.autoLockIn > ConnectionsManager.getInstance(UserConfig.selectedAccount).getCurrentTime()) || ConnectionsManager.getInstance(UserConfig.selectedAccount).getCurrentTime() + 5 < SharedConfig.lastPauseTime));
    }

    public static void shakeView(final View view, final float x, final int num) {
        if (view == null) {
            return;
        }
        if (num == 6) {
            view.setTranslationX(0.0f);
            return;
        }
        AnimatorSet animatorSet = new AnimatorSet();
        animatorSet.playTogether(ObjectAnimator.ofFloat(view, "translationX", dp(x)));
        animatorSet.setDuration(50L);
        animatorSet.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.messenger.AndroidUtilities.1
            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationEnd(Animator animation) {
                AndroidUtilities.shakeView(view, num == 5 ? 0.0f : -x, num + 1);
            }
        });
        animatorSet.start();
    }

    public static void checkForCrashes(Activity context) {
    }

    public static void checkForUpdates(Activity context) {
        boolean z = BuildVars.DEBUG_VERSION;
    }

    public static void unregisterUpdates() {
        boolean z = BuildVars.DEBUG_VERSION;
    }

    public static void addToClipboard(CharSequence str) {
        try {
            ClipboardManager clipboard = (ClipboardManager) ApplicationLoader.applicationContext.getSystemService("clipboard");
            ClipData clip = ClipData.newPlainText("label", str);
            clipboard.setPrimaryClip(clip);
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    public static void addMediaToGallery(String fromPath) {
        if (fromPath == null) {
            return;
        }
        File f = new File(fromPath);
        Uri contentUri = Uri.fromFile(f);
        addMediaToGallery(contentUri);
    }

    public static void addMediaToGallery(Uri uri) {
        if (uri == null) {
            return;
        }
        try {
            Intent mediaScanIntent = new Intent("android.intent.action.MEDIA_SCANNER_SCAN_FILE");
            mediaScanIntent.setData(uri);
            ApplicationLoader.applicationContext.sendBroadcast(mediaScanIntent);
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    public static File getAlbumDir(boolean secretChat) {
        if (secretChat || (Build.VERSION.SDK_INT >= 23 && ApplicationLoader.applicationContext.checkSelfPermission("android.permission.WRITE_EXTERNAL_STORAGE") != 0)) {
            return FileLoader.getDirectory(4);
        }
        File storageDir = null;
        if ("mounted".equals(Environment.getExternalStorageState())) {
            storageDir = new File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_PICTURES), "Sbcc");
            if (!storageDir.mkdirs() && !storageDir.exists()) {
                if (BuildVars.LOGS_ENABLED) {
                    FileLog.d("failed to create directory");
                }
                File storageDir2 = ApplicationLoader.applicationContext.getExternalFilesDir("Sbcc");
                if (!storageDir2.mkdirs()) {
                    storageDir2.exists();
                    return null;
                }
                return null;
            }
        } else if (BuildVars.LOGS_ENABLED) {
            FileLog.d("External storage is not mounted READ/WRITE.");
        }
        return storageDir;
    }

    /* JADX WARN: Removed duplicated region for block: B:30:0x0098  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static java.lang.String getPath(android.net.Uri r13) {
        /*
            Method dump skipped, instruction units count: 258
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.AndroidUtilities.getPath(android.net.Uri):java.lang.String");
    }

    /* JADX WARN: Code restructure failed: missing block: B:12:0x003b, code lost:
    
        if (r3.startsWith("file://") == false) goto L19;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static java.lang.String getDataColumn(android.content.Context r9, android.net.Uri r10, java.lang.String r11, java.lang.String[] r12) {
        /*
            java.lang.String r0 = "_data"
            java.lang.String r1 = "_data"
            java.lang.String[] r4 = new java.lang.String[]{r1}
            r8 = 0
            android.content.ContentResolver r2 = r9.getContentResolver()     // Catch: java.lang.Exception -> L60
            r7 = 0
            r3 = r10
            r5 = r11
            r6 = r12
            android.database.Cursor r2 = r2.query(r3, r4, r5, r6, r7)     // Catch: java.lang.Exception -> L60
            if (r2 == 0) goto L5a
            boolean r3 = r2.moveToFirst()     // Catch: java.lang.Throwable -> L4c
            if (r3 == 0) goto L5a
            int r1 = r2.getColumnIndexOrThrow(r1)     // Catch: java.lang.Throwable -> L4c
            java.lang.String r3 = r2.getString(r1)     // Catch: java.lang.Throwable -> L4c
            java.lang.String r5 = "content://"
            boolean r5 = r3.startsWith(r5)     // Catch: java.lang.Throwable -> L4c
            if (r5 != 0) goto L45
            java.lang.String r5 = "/"
            boolean r5 = r3.startsWith(r5)     // Catch: java.lang.Throwable -> L4c
            if (r5 != 0) goto L3e
            java.lang.String r5 = "file://"
            boolean r5 = r3.startsWith(r5)     // Catch: java.lang.Throwable -> L4c
            if (r5 != 0) goto L3e
            goto L45
        L3e:
            if (r2 == 0) goto L44
            r2.close()     // Catch: java.lang.Exception -> L60
        L44:
            return r3
        L45:
            if (r2 == 0) goto L4b
            r2.close()     // Catch: java.lang.Exception -> L60
        L4b:
            return r8
        L4c:
            r1 = move-exception
            throw r1     // Catch: java.lang.Throwable -> L4e
        L4e:
            r3 = move-exception
            if (r2 == 0) goto L59
            r2.close()     // Catch: java.lang.Throwable -> L55
            goto L59
        L55:
            r5 = move-exception
            r1.addSuppressed(r5)     // Catch: java.lang.Exception -> L60
        L59:
            throw r3     // Catch: java.lang.Exception -> L60
        L5a:
            if (r2 == 0) goto L5f
            r2.close()     // Catch: java.lang.Exception -> L60
        L5f:
            goto L61
        L60:
            r1 = move-exception
        L61:
            return r8
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.AndroidUtilities.getDataColumn(android.content.Context, android.net.Uri, java.lang.String, java.lang.String[]):java.lang.String");
    }

    public static boolean isExternalStorageDocument(Uri uri) {
        return "com.android.externalstorage.documents".equals(uri.getAuthority());
    }

    public static boolean isDownloadsDocument(Uri uri) {
        return "com.android.providers.downloads.documents".equals(uri.getAuthority());
    }

    public static boolean isMediaDocument(Uri uri) {
        return "com.android.providers.media.documents".equals(uri.getAuthority());
    }

    public static File generatePicturePath() {
        return generatePicturePath(false);
    }

    public static File generatePicturePath(boolean secretChat) {
        try {
            File storageDir = getAlbumDir(secretChat);
            Date date = new Date();
            date.setTime(System.currentTimeMillis() + ((long) Utilities.random.nextInt(1000)) + 1);
            String timeStamp = new SimpleDateFormat("yyyyMMdd_HHmmss_SSS", Locale.US).format(date);
            return new File(storageDir, "IMG_" + timeStamp + ".jpg");
        } catch (Exception e) {
            FileLog.e(e);
            return null;
        }
    }

    public static CharSequence generateSearchName(String name, String name2, String q) {
        if (name == null && name2 == null) {
            return "";
        }
        SpannableStringBuilder builder = new SpannableStringBuilder();
        String wholeString = name;
        if (wholeString == null || wholeString.length() == 0) {
            wholeString = name2;
        } else if (name2 != null && name2.length() != 0) {
            wholeString = wholeString + " " + name2;
        }
        String wholeString2 = wholeString.trim();
        String lower = " " + wholeString2.toLowerCase();
        int lastIndex = 0;
        while (true) {
            int index = lower.indexOf(" " + q, lastIndex);
            if (index == -1) {
                break;
            }
            int idx = index - (index == 0 ? 0 : 1);
            int end = q.length() + (index == 0 ? 0 : 1) + idx;
            if (lastIndex != 0 && lastIndex != idx + 1) {
                builder.append((CharSequence) wholeString2.substring(lastIndex, idx));
            } else if (lastIndex == 0 && idx != 0) {
                builder.append((CharSequence) wholeString2.substring(0, idx));
            }
            String query = wholeString2.substring(idx, Math.min(wholeString2.length(), end));
            if (query.startsWith(" ")) {
                builder.append((CharSequence) " ");
            }
            String query2 = query.trim();
            int start = builder.length();
            builder.append((CharSequence) query2);
            builder.setSpan(new ForegroundColorSpan(Theme.getColor(Theme.key_windowBackgroundWhiteBlueText4)), start, query2.length() + start, 33);
            lastIndex = end;
        }
        if (lastIndex != -1 && lastIndex < wholeString2.length()) {
            builder.append((CharSequence) wholeString2.substring(lastIndex));
        }
        return builder;
    }

    public static boolean isAirplaneModeOn() {
        return Build.VERSION.SDK_INT < 17 ? Settings.System.getInt(ApplicationLoader.applicationContext.getContentResolver(), "airplane_mode_on", 0) != 0 : Settings.Global.getInt(ApplicationLoader.applicationContext.getContentResolver(), "airplane_mode_on", 0) != 0;
    }

    public static File generateVideoPath() {
        return generateVideoPath(false);
    }

    public static File generateVideoPath(boolean secretChat) {
        try {
            File storageDir = getAlbumDir(secretChat);
            Date date = new Date();
            date.setTime(System.currentTimeMillis() + ((long) Utilities.random.nextInt(1000)) + 1);
            String timeStamp = new SimpleDateFormat("yyyyMMdd_HHmmss_SSS", Locale.US).format(date);
            return new File(storageDir, "VID_" + timeStamp + ".mp4");
        } catch (Exception e) {
            FileLog.e(e);
            return null;
        }
    }

    public static String formatFileSize(long size) {
        return formatFileSize(size, false);
    }

    public static String formatFileSize(long size, boolean removeZero) {
        if (size < 1024) {
            return String.format("%d B", Long.valueOf(size));
        }
        if (size < 1048576) {
            float value = size / 1024.0f;
            return (removeZero && (value - ((float) ((int) value))) * 10.0f == 0.0f) ? String.format("%d KB", Integer.valueOf((int) value)) : String.format("%.1f KB", Float.valueOf(value));
        }
        if (size < 1073741824) {
            float value2 = (size / 1024.0f) / 1024.0f;
            return (removeZero && (value2 - ((float) ((int) value2))) * 10.0f == 0.0f) ? String.format("%d MB", Integer.valueOf((int) value2)) : String.format("%.1f MB", Float.valueOf(value2));
        }
        float value3 = ((size / 1024.0f) / 1024.0f) / 1024.0f;
        return (removeZero && (value3 - ((float) ((int) value3))) * 10.0f == 0.0f) ? String.format("%d GB", Integer.valueOf((int) value3)) : String.format("%.1f GB", Float.valueOf(value3));
    }

    public static byte[] decodeQuotedPrintable(byte[] bytes) {
        if (bytes == null) {
            return null;
        }
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        int i = 0;
        while (i < bytes.length) {
            int b = bytes[i];
            if (b == 61) {
                int i2 = i + 1;
                try {
                    int u = Character.digit((char) bytes[i2], 16);
                    i = i2 + 1;
                    int l = Character.digit((char) bytes[i], 16);
                    buffer.write((char) ((u << 4) + l));
                } catch (Exception e) {
                    FileLog.e(e);
                    return null;
                }
            } else {
                buffer.write(b);
            }
            i++;
        }
        byte[] array = buffer.toByteArray();
        try {
            buffer.close();
        } catch (Exception e2) {
            FileLog.e(e2);
        }
        return array;
    }

    public static boolean copyFile(InputStream sourceFile, File destFile) throws IOException {
        OutputStream out = new FileOutputStream(destFile);
        byte[] buf = new byte[4096];
        while (true) {
            int len = sourceFile.read(buf);
            if (len > 0) {
                Thread.yield();
                out.write(buf, 0, len);
            } else {
                out.close();
                return true;
            }
        }
    }

    public static boolean copyFile(File sourceFile, File destFile) throws IOException {
        if (sourceFile.equals(destFile)) {
            return true;
        }
        if (!destFile.exists()) {
            destFile.createNewFile();
        }
        try {
            FileInputStream source = new FileInputStream(sourceFile);
            try {
                FileOutputStream destination = new FileOutputStream(destFile);
                try {
                    destination.getChannel().transferFrom(source.getChannel(), 0L, source.getChannel().size());
                    destination.close();
                    source.close();
                    return true;
                } finally {
                }
            } finally {
            }
        } catch (Exception e) {
            FileLog.e(e);
            return false;
        }
    }

    public static byte[] calcAuthKeyHash(byte[] auth_key) {
        byte[] sha1 = Utilities.computeSHA1(auth_key);
        byte[] key_hash = new byte[16];
        System.arraycopy(sha1, 0, key_hash, 0, 16);
        return key_hash;
    }

    public static void openDocument(MessageObject message, Activity activity, BaseFragment parentFragment) {
        TLRPC.Document document;
        File f;
        if (message == null || (document = message.getDocument()) == null) {
            return;
        }
        File f2 = null;
        String fileName = message.messageOwner.media != null ? FileLoader.getAttachFileName(document) : "";
        if (message.messageOwner.attachPath != null && message.messageOwner.attachPath.length() != 0) {
            f2 = new File(message.messageOwner.attachPath);
        }
        if (f2 == null || (f2 != null && !f2.exists())) {
            f = FileLoader.getPathToMessage(message.messageOwner);
        } else {
            f = f2;
        }
        if (f == null || !f.exists()) {
            return;
        }
        if (parentFragment != null && f.getName().toLowerCase().endsWith("attheme")) {
            Theme.ThemeInfo themeInfo = Theme.applyThemeFile(f, message.getDocumentName(), null, true);
            if (themeInfo != null) {
                parentFragment.presentFragment(new ThemePreviewActivity(themeInfo));
                return;
            }
            AlertDialog.Builder builder = new AlertDialog.Builder(activity);
            builder.setTitle(LocaleController.getString("AppName", mpEIGo.juqQQs.esbSDO.R.string.AppName));
            builder.setMessage(LocaleController.getString("IncorrectTheme", mpEIGo.juqQQs.esbSDO.R.string.IncorrectTheme));
            builder.setPositiveButton(LocaleController.getString("OK", mpEIGo.juqQQs.esbSDO.R.string.OK), null);
            parentFragment.showDialog(builder.create());
            return;
        }
        String realMimeType = null;
        try {
            Intent intent = new Intent("android.intent.action.VIEW");
            intent.setFlags(1);
            MimeTypeMap myMime = MimeTypeMap.getSingleton();
            int idx = fileName.lastIndexOf(46);
            if (idx != -1) {
                String ext = fileName.substring(idx + 1);
                realMimeType = myMime.getMimeTypeFromExtension(ext.toLowerCase());
                if (realMimeType == null && ((realMimeType = document.mime_type) == null || realMimeType.length() == 0)) {
                    realMimeType = null;
                }
            }
            if (Build.VERSION.SDK_INT >= 24) {
                intent.setDataAndType(FileProvider.getUriForFile(activity, "singansfg.uwrkaxlmjj.sdancsuhsfj.provider", f), realMimeType != null ? realMimeType : "text/plain");
            } else {
                intent.setDataAndType(Uri.fromFile(f), realMimeType != null ? realMimeType : "text/plain");
            }
            if (realMimeType != null) {
                try {
                    activity.startActivityForResult(intent, SlidingItemMenuRecyclerView.DEFAULT_ITEM_SCROLL_DURATION);
                    return;
                } catch (Exception e) {
                    if (Build.VERSION.SDK_INT >= 24) {
                        intent.setDataAndType(FileProvider.getUriForFile(activity, "singansfg.uwrkaxlmjj.sdancsuhsfj.provider", f), "text/plain");
                    } else {
                        intent.setDataAndType(Uri.fromFile(f), "text/plain");
                    }
                    activity.startActivityForResult(intent, SlidingItemMenuRecyclerView.DEFAULT_ITEM_SCROLL_DURATION);
                    return;
                }
            }
            activity.startActivityForResult(intent, SlidingItemMenuRecyclerView.DEFAULT_ITEM_SCROLL_DURATION);
        } catch (Exception e2) {
            if (activity == null) {
                return;
            }
            AlertDialog.Builder builder2 = new AlertDialog.Builder(activity);
            builder2.setTitle(LocaleController.getString("AppName", mpEIGo.juqQQs.esbSDO.R.string.AppName));
            builder2.setPositiveButton(LocaleController.getString("OK", mpEIGo.juqQQs.esbSDO.R.string.OK), null);
            builder2.setMessage(LocaleController.formatString("NoHandleAppInstalled", mpEIGo.juqQQs.esbSDO.R.string.NoHandleAppInstalled, message.getDocument().mime_type));
            if (parentFragment != null) {
                parentFragment.showDialog(builder2.create());
            } else {
                builder2.show();
            }
        }
    }

    public static void openForView(MessageObject message, final Activity activity) {
        File f = null;
        String fileName = message.getFileName();
        if (message.messageOwner.attachPath != null && message.messageOwner.attachPath.length() != 0) {
            f = new File(message.messageOwner.attachPath);
        }
        if (f == null || !f.exists()) {
            f = FileLoader.getPathToMessage(message.messageOwner);
        }
        if (f != null && f.exists()) {
            String realMimeType = null;
            Intent intent = new Intent("android.intent.action.VIEW");
            intent.setFlags(1);
            MimeTypeMap myMime = MimeTypeMap.getSingleton();
            int idx = fileName.lastIndexOf(46);
            if (idx != -1) {
                String ext = fileName.substring(idx + 1);
                realMimeType = myMime.getMimeTypeFromExtension(ext.toLowerCase());
                if (realMimeType == null) {
                    if (message.type == 9 || message.type == 0) {
                        realMimeType = message.getDocument().mime_type;
                    }
                    if (realMimeType == null || realMimeType.length() == 0) {
                        realMimeType = null;
                    }
                }
            }
            if (Build.VERSION.SDK_INT >= 26 && realMimeType != null && realMimeType.equals("application/vnd.android.package-archive") && !ApplicationLoader.applicationContext.getPackageManager().canRequestPackageInstalls()) {
                AlertDialog.Builder builder = new AlertDialog.Builder(activity);
                builder.setTitle(LocaleController.getString("AppName", mpEIGo.juqQQs.esbSDO.R.string.AppName));
                builder.setMessage(LocaleController.getString("ApkRestricted", mpEIGo.juqQQs.esbSDO.R.string.ApkRestricted));
                builder.setPositiveButton(LocaleController.getString("PermissionOpenSettings", mpEIGo.juqQQs.esbSDO.R.string.PermissionOpenSettings), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$AndroidUtilities$5FIjWax7NXYMCFOnxdadIOGRHgM
                    @Override // android.content.DialogInterface.OnClickListener
                    public final void onClick(DialogInterface dialogInterface, int i) {
                        AndroidUtilities.lambda$openForView$2(activity, dialogInterface, i);
                    }
                });
                builder.setNegativeButton(LocaleController.getString("Cancel", mpEIGo.juqQQs.esbSDO.R.string.Cancel), null);
                builder.show();
                return;
            }
            if (Build.VERSION.SDK_INT >= 24) {
                intent.setDataAndType(FileProvider.getUriForFile(activity, "singansfg.uwrkaxlmjj.sdancsuhsfj.provider", f), realMimeType != null ? realMimeType : "text/plain");
            } else {
                intent.setDataAndType(Uri.fromFile(f), realMimeType != null ? realMimeType : "text/plain");
            }
            if (realMimeType != null) {
                try {
                    activity.startActivityForResult(intent, SlidingItemMenuRecyclerView.DEFAULT_ITEM_SCROLL_DURATION);
                    return;
                } catch (Exception e) {
                    if (Build.VERSION.SDK_INT >= 24) {
                        intent.setDataAndType(FileProvider.getUriForFile(activity, "singansfg.uwrkaxlmjj.sdancsuhsfj.provider", f), "text/plain");
                    } else {
                        intent.setDataAndType(Uri.fromFile(f), "text/plain");
                    }
                    activity.startActivityForResult(intent, SlidingItemMenuRecyclerView.DEFAULT_ITEM_SCROLL_DURATION);
                    return;
                }
            }
            activity.startActivityForResult(intent, SlidingItemMenuRecyclerView.DEFAULT_ITEM_SCROLL_DURATION);
        }
    }

    static /* synthetic */ void lambda$openForView$2(Activity activity, DialogInterface dialogInterface, int i) {
        try {
            activity.startActivity(new Intent("android.settings.MANAGE_UNKNOWN_APP_SOURCES", Uri.parse("package:" + activity.getPackageName())));
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    public static void openForView(TLObject media, Activity activity) {
        if (media == null || activity == null) {
            return;
        }
        String fileName = FileLoader.getAttachFileName(media);
        File f = FileLoader.getPathToAttach(media, true);
        if (f != null && f.exists()) {
            String realMimeType = null;
            Intent intent = new Intent("android.intent.action.VIEW");
            intent.setFlags(1);
            MimeTypeMap myMime = MimeTypeMap.getSingleton();
            int idx = fileName.lastIndexOf(46);
            if (idx != -1) {
                String ext = fileName.substring(idx + 1);
                realMimeType = myMime.getMimeTypeFromExtension(ext.toLowerCase());
                if (realMimeType == null) {
                    if (media instanceof TLRPC.TL_document) {
                        realMimeType = ((TLRPC.TL_document) media).mime_type;
                    }
                    if (realMimeType == null || realMimeType.length() == 0) {
                        realMimeType = null;
                    }
                }
            }
            if (Build.VERSION.SDK_INT >= 24) {
                intent.setDataAndType(FileProvider.getUriForFile(activity, "singansfg.uwrkaxlmjj.sdancsuhsfj.provider", f), realMimeType != null ? realMimeType : "text/plain");
            } else {
                intent.setDataAndType(Uri.fromFile(f), realMimeType != null ? realMimeType : "text/plain");
            }
            if (realMimeType != null) {
                try {
                    activity.startActivityForResult(intent, SlidingItemMenuRecyclerView.DEFAULT_ITEM_SCROLL_DURATION);
                    return;
                } catch (Exception e) {
                    if (Build.VERSION.SDK_INT >= 24) {
                        intent.setDataAndType(FileProvider.getUriForFile(activity, "singansfg.uwrkaxlmjj.sdancsuhsfj.provider", f), "text/plain");
                    } else {
                        intent.setDataAndType(Uri.fromFile(f), "text/plain");
                    }
                    activity.startActivityForResult(intent, SlidingItemMenuRecyclerView.DEFAULT_ITEM_SCROLL_DURATION);
                    return;
                }
            }
            activity.startActivityForResult(intent, SlidingItemMenuRecyclerView.DEFAULT_ITEM_SCROLL_DURATION);
        }
    }

    public static boolean isBannedForever(TLRPC.TL_chatBannedRights rights) {
        return rights == null || Math.abs(((long) rights.until_date) - (System.currentTimeMillis() / 1000)) > 157680000;
    }

    public static void setRectToRect(Matrix matrix, RectF src, RectF dst, int rotation, boolean translate) {
        float sx;
        float sy;
        float tx;
        float ty;
        float diff;
        boolean xLarger = false;
        if (rotation == 90 || rotation == 270) {
            float sx2 = dst.height();
            sx = sx2 / src.width();
            sy = dst.width() / src.height();
        } else {
            sx = dst.width() / src.width();
            sy = dst.height() / src.height();
        }
        if (sx < sy) {
            sx = sy;
            xLarger = true;
        } else {
            sy = sx;
        }
        if (translate) {
            matrix.setTranslate(dst.left, dst.top);
        }
        if (rotation == 90) {
            matrix.preRotate(90.0f);
            matrix.preTranslate(0.0f, -dst.width());
        } else if (rotation == 180) {
            matrix.preRotate(180.0f);
            matrix.preTranslate(-dst.width(), -dst.height());
        } else if (rotation == 270) {
            matrix.preRotate(270.0f);
            matrix.preTranslate(-dst.height(), 0.0f);
        }
        if (translate) {
            tx = (-src.left) * sx;
            ty = (-src.top) * sy;
        } else {
            float tx2 = dst.left;
            tx = tx2 - (src.left * sx);
            ty = dst.top - (src.top * sy);
        }
        if (xLarger) {
            diff = dst.width() - (src.width() * sy);
        } else {
            float diff2 = dst.height();
            diff = diff2 - (src.height() * sy);
        }
        float diff3 = diff / 2.0f;
        if (xLarger) {
            tx += diff3;
        } else {
            ty += diff3;
        }
        matrix.preScale(sx, sy);
        if (translate) {
            matrix.preTranslate(tx, ty);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:49:0x00fe A[Catch: Exception -> 0x011c, TRY_LEAVE, TryCatch #0 {Exception -> 0x011c, blocks: (B:5:0x0008, B:8:0x0012, B:10:0x0018, B:12:0x0023, B:15:0x0035, B:32:0x00a9, B:34:0x00af, B:36:0x00bb, B:38:0x00c1, B:40:0x00c9, B:42:0x00d1, B:47:0x00f8, B:49:0x00fe, B:59:0x0116, B:18:0x0043, B:20:0x004b, B:23:0x005f, B:25:0x0065, B:27:0x006b, B:29:0x0071), top: B:66:0x0008 }] */
    /* JADX WARN: Removed duplicated region for block: B:69:? A[ADDED_TO_REGION, RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static boolean handleProxyIntent(android.app.Activity r19, android.content.Intent r20) {
        /*
            Method dump skipped, instruction units count: 287
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.AndroidUtilities.handleProxyIntent(android.app.Activity, android.content.Intent):boolean");
    }

    public static boolean shouldEnableAnimation() {
        if (Build.VERSION.SDK_INT < 26 || Build.VERSION.SDK_INT >= 28) {
            return true;
        }
        PowerManager powerManager = (PowerManager) ApplicationLoader.applicationContext.getSystemService("power");
        if (powerManager.isPowerSaveMode()) {
            return false;
        }
        float scale = Settings.Global.getFloat(ApplicationLoader.applicationContext.getContentResolver(), "animator_duration_scale", 1.0f);
        return scale > 0.0f;
    }

    public static void showProxyAlert(Activity activity, final String address, final String port, final String user, final String password, final String secret) {
        BottomSheet.Builder builder = new BottomSheet.Builder(activity);
        final Runnable dismissRunnable = builder.getDismissRunnable();
        builder.setApplyTopPadding(false);
        builder.setApplyBottomPadding(false);
        LinearLayout linearLayout = new LinearLayout(activity);
        builder.setCustomView(linearLayout);
        boolean z = true;
        linearLayout.setOrientation(1);
        if (!TextUtils.isEmpty(secret)) {
            TextView titleTextView = new TextView(activity);
            titleTextView.setText(LocaleController.getString("UseProxySettingsTips", mpEIGo.juqQQs.esbSDO.R.string.UseProxySettingsTips));
            titleTextView.setTextColor(Theme.getColor(Theme.key_dialogTextGray4));
            titleTextView.setTextSize(1, 14.0f);
            titleTextView.setGravity(49);
            linearLayout.addView(titleTextView, LayoutHelper.createLinear(-2, -2, (LocaleController.isRTL ? 5 : 3) | 48, 17, 8, 17, 8));
            View lineView = new View(activity);
            lineView.setBackgroundColor(Theme.getColor(Theme.key_divider));
            linearLayout.addView(lineView, new LinearLayout.LayoutParams(-1, 1));
        }
        int a = 0;
        for (int i = 5; a < i; i = 5) {
            String text = null;
            String detail = null;
            if (a == 0) {
                text = address;
                detail = LocaleController.getString("UseProxyAddress", mpEIGo.juqQQs.esbSDO.R.string.UseProxyAddress);
            } else if (a != z) {
                if (a == 2) {
                    text = secret;
                    detail = LocaleController.getString("UseProxySecret", mpEIGo.juqQQs.esbSDO.R.string.UseProxySecret);
                } else if (a == 3) {
                    text = user;
                    detail = LocaleController.getString("UseProxyUsername", mpEIGo.juqQQs.esbSDO.R.string.UseProxyUsername);
                } else if (a == 4) {
                    text = password;
                    detail = LocaleController.getString("UseProxyPassword", mpEIGo.juqQQs.esbSDO.R.string.UseProxyPassword);
                }
            } else {
                text = "" + port;
                detail = LocaleController.getString("UseProxyPort", mpEIGo.juqQQs.esbSDO.R.string.UseProxyPort);
            }
            if (!TextUtils.isEmpty(text)) {
                TextDetailSettingsCell cell = new TextDetailSettingsCell(activity);
                cell.setTextAndValue(text, detail, z);
                cell.getTextView().setTextColor(Theme.getColor(Theme.key_dialogTextBlack));
                cell.getValueTextView().setTextColor(Theme.getColor(Theme.key_dialogTextGray3));
                linearLayout.addView(cell, LayoutHelper.createLinear(-1, -2));
                if (a == 2) {
                    break;
                }
            }
            a++;
            z = true;
        }
        PickerBottomLayout pickerBottomLayout = new PickerBottomLayout(activity, false);
        pickerBottomLayout.setBackgroundColor(Theme.getColor(Theme.key_dialogBackground));
        linearLayout.addView(pickerBottomLayout, LayoutHelper.createFrame(-1, 48, 83));
        pickerBottomLayout.cancelButton.setPadding(dp(18.0f), 0, dp(18.0f), 0);
        pickerBottomLayout.cancelButton.setTextColor(Theme.getColor(Theme.key_dialogTextBlue2));
        pickerBottomLayout.cancelButton.setText(LocaleController.getString("Cancel", mpEIGo.juqQQs.esbSDO.R.string.Cancel).toUpperCase());
        pickerBottomLayout.cancelButton.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$AndroidUtilities$AUn1Bwny_tscOS0pnoTopjuwirY
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                dismissRunnable.run();
            }
        });
        pickerBottomLayout.doneButtonTextView.setTextColor(Theme.getColor(Theme.key_dialogTextBlue2));
        pickerBottomLayout.doneButton.setPadding(dp(18.0f), 0, dp(18.0f), 0);
        pickerBottomLayout.doneButtonBadgeTextView.setVisibility(8);
        pickerBottomLayout.doneButtonTextView.setText(LocaleController.getString("ConnectingConnectProxy", mpEIGo.juqQQs.esbSDO.R.string.ConnectingConnectProxy).toUpperCase());
        pickerBottomLayout.doneButton.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$AndroidUtilities$tLMmr0SbweFocGUDYcZSwxFOsgU
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                AndroidUtilities.lambda$showProxyAlert$4(address, port, secret, password, user, dismissRunnable, view);
            }
        });
        builder.show();
    }

    static /* synthetic */ void lambda$showProxyAlert$4(String address, String port, String secret, String password, String user, Runnable dismissRunnable, View v) {
        SharedConfig.ProxyInfo info;
        SharedPreferences.Editor editor = MessagesController.getGlobalMainSettings().edit();
        editor.putBoolean("proxy_enabled", true);
        editor.putString("proxy_ip", address);
        int p = Utilities.parseInt(port).intValue();
        editor.putInt("proxy_port", p);
        if (TextUtils.isEmpty(secret)) {
            editor.remove("proxy_secret");
            if (TextUtils.isEmpty(password)) {
                editor.remove("proxy_pass");
            } else {
                editor.putString("proxy_pass", password);
            }
            if (TextUtils.isEmpty(user)) {
                editor.remove("proxy_user");
            } else {
                editor.putString("proxy_user", user);
            }
            info = new SharedConfig.ProxyInfo(address, p, user, password, "");
        } else {
            editor.remove("proxy_pass");
            editor.remove("proxy_user");
            editor.putString("proxy_secret", secret);
            info = new SharedConfig.ProxyInfo(address, p, "", "", secret);
        }
        editor.commit();
        SharedConfig.currentProxy = SharedConfig.addProxy(info);
        ConnectionsManager.setProxySettings(true, address, p, user, password, secret);
        NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.proxySettingsChanged, new Object[0]);
        dismissRunnable.run();
    }

    public static String getSystemProperty(String key) {
        try {
            return (String) Class.forName("android.os.SystemProperties").getMethod("get", String.class).invoke(null, key);
        } catch (Exception e) {
            return null;
        }
    }

    public static CharSequence concat(CharSequence... text) {
        if (text.length == 0) {
            return "";
        }
        int i = 0;
        if (text.length == 1) {
            return text[0];
        }
        boolean spanned = false;
        int length = text.length;
        int i2 = 0;
        while (true) {
            if (i2 >= length) {
                break;
            }
            if (!(text[i2] instanceof Spanned)) {
                i2++;
            } else {
                spanned = true;
                break;
            }
        }
        if (spanned) {
            SpannableStringBuilder ssb = new SpannableStringBuilder();
            int length2 = text.length;
            while (i < length2) {
                CharSequence piece = text[i];
                ssb.append(piece == null ? "null" : piece);
                i++;
            }
            return new SpannedString(ssb);
        }
        StringBuilder sb = new StringBuilder();
        int length3 = text.length;
        while (i < length3) {
            sb.append(text[i]);
            i++;
        }
        return sb.toString();
    }

    public static float[] RGBtoHSB(int r, int g, int b) {
        float saturation;
        float hue;
        float hue2;
        float[] hsbvals = new float[3];
        int cmax = r > g ? r : g;
        if (b > cmax) {
            cmax = b;
        }
        int cmin = r < g ? r : g;
        if (b < cmin) {
            cmin = b;
        }
        float brightness = cmax / 255.0f;
        if (cmax != 0) {
            saturation = (cmax - cmin) / cmax;
        } else {
            saturation = 0.0f;
        }
        if (saturation == 0.0f) {
            hue2 = 0.0f;
        } else {
            float redc = (cmax - r) / (cmax - cmin);
            float greenc = (cmax - g) / (cmax - cmin);
            float bluec = (cmax - b) / (cmax - cmin);
            if (r == cmax) {
                hue = bluec - greenc;
            } else if (g == cmax) {
                hue = (2.0f + redc) - bluec;
            } else {
                hue = (4.0f + greenc) - redc;
            }
            float hue3 = hue / 6.0f;
            if (hue3 >= 0.0f) {
                hue2 = hue3;
            } else {
                hue2 = 1.0f + hue3;
            }
        }
        hsbvals[0] = hue2;
        hsbvals[1] = saturation;
        hsbvals[2] = brightness;
        return hsbvals;
    }

    public static int HSBtoRGB(float hue, float saturation, float brightness) {
        int r = 0;
        int g = 0;
        int b = 0;
        if (saturation == 0.0f) {
            int i = (int) ((255.0f * brightness) + 0.5f);
            b = i;
            g = i;
            r = i;
        } else {
            float h = (hue - ((float) Math.floor(hue))) * 6.0f;
            float f = h - ((float) Math.floor(h));
            float p = (1.0f - saturation) * brightness;
            float q = (1.0f - (saturation * f)) * brightness;
            float t = (1.0f - ((1.0f - f) * saturation)) * brightness;
            int i2 = (int) h;
            if (i2 == 0) {
                r = (int) ((brightness * 255.0f) + 0.5f);
                g = (int) ((t * 255.0f) + 0.5f);
                b = (int) ((255.0f * p) + 0.5f);
            } else if (i2 == 1) {
                r = (int) ((q * 255.0f) + 0.5f);
                g = (int) ((brightness * 255.0f) + 0.5f);
                b = (int) ((255.0f * p) + 0.5f);
            } else if (i2 == 2) {
                r = (int) ((p * 255.0f) + 0.5f);
                g = (int) ((brightness * 255.0f) + 0.5f);
                b = (int) ((255.0f * t) + 0.5f);
            } else if (i2 == 3) {
                r = (int) ((p * 255.0f) + 0.5f);
                g = (int) ((q * 255.0f) + 0.5f);
                b = (int) ((255.0f * brightness) + 0.5f);
            } else if (i2 == 4) {
                r = (int) ((t * 255.0f) + 0.5f);
                g = (int) ((p * 255.0f) + 0.5f);
                b = (int) ((255.0f * brightness) + 0.5f);
            } else if (i2 == 5) {
                r = (int) ((brightness * 255.0f) + 0.5f);
                g = (int) ((p * 255.0f) + 0.5f);
                b = (int) ((255.0f * q) + 0.5f);
            }
        }
        return (-16777216) | ((r & 255) << 16) | ((g & 255) << 8) | (b & 255);
    }

    public static int getPatternColor(int color) {
        float[] hsb = RGBtoHSB(Color.red(color), Color.green(color), Color.blue(color));
        if (hsb[1] > 0.0f || (hsb[2] < 1.0f && hsb[2] > 0.0f)) {
            hsb[1] = Math.min(1.0f, hsb[1] + 0.05f + ((1.0f - hsb[1]) * 0.1f));
        }
        if (hsb[2] > 0.5f) {
            hsb[2] = Math.max(0.0f, hsb[2] * 0.65f);
        } else {
            hsb[2] = Math.max(0.0f, Math.min(1.0f, 1.0f - (hsb[2] * 0.65f)));
        }
        return HSBtoRGB(hsb[0], hsb[1], hsb[2]) & 1728053247;
    }

    public static int getPatternSideColor(int color) {
        float[] hsb = RGBtoHSB(Color.red(color), Color.green(color), Color.blue(color));
        hsb[1] = Math.min(1.0f, hsb[1] + 0.05f);
        if (hsb[2] > 0.5f) {
            hsb[2] = Math.max(0.0f, hsb[2] * 0.9f);
        } else {
            hsb[2] = Math.max(0.0f, hsb[2] * 0.9f);
        }
        return HSBtoRGB(hsb[0], hsb[1], hsb[2]) | (-16777216);
    }

    public static String getWallPaperUrl(Object object, int currentAccount) {
        if (object instanceof TLRPC.TL_wallPaper) {
            TLRPC.TL_wallPaper wallPaper = (TLRPC.TL_wallPaper) object;
            String link = DefaultWebClient.HTTPS_SCHEME + MessagesController.getInstance(currentAccount).linkPrefix + "/bg/" + wallPaper.slug;
            StringBuilder modes = new StringBuilder();
            if (wallPaper.settings != null) {
                if (wallPaper.settings.blur) {
                    modes.append("blur");
                }
                if (wallPaper.settings.motion) {
                    if (modes.length() > 0) {
                        modes.append(Marker.ANY_NON_NULL_MARKER);
                    }
                    modes.append("motion");
                }
            }
            if (modes.length() > 0) {
                return link + "?mode=" + modes.toString();
            }
            return link;
        }
        if (object instanceof WallpapersListActivity.ColorWallpaper) {
            WallpapersListActivity.ColorWallpaper wallPaper2 = (WallpapersListActivity.ColorWallpaper) object;
            String color = String.format("%02x%02x%02x", Integer.valueOf(((byte) (wallPaper2.color >> 16)) & UByte.MAX_VALUE), Integer.valueOf(((byte) (wallPaper2.color >> 8)) & UByte.MAX_VALUE), Byte.valueOf((byte) (wallPaper2.color & 255))).toLowerCase();
            if (wallPaper2.pattern != null) {
                String link2 = DefaultWebClient.HTTPS_SCHEME + MessagesController.getInstance(currentAccount).linkPrefix + "/bg/" + wallPaper2.pattern.slug + "?intensity=" + ((int) (wallPaper2.intensity * 100.0f)) + "&bg_color=" + color;
                return link2;
            }
            String link3 = DefaultWebClient.HTTPS_SCHEME + MessagesController.getInstance(currentAccount).linkPrefix + "/bg/" + color;
            return link3;
        }
        return null;
    }

    public static float distanceInfluenceForSnapDuration(float f) {
        return (float) Math.sin((f - 0.5f) * 0.47123894f);
    }

    public static void makeAccessibilityAnnouncement(CharSequence what) {
        AccessibilityManager am = (AccessibilityManager) ApplicationLoader.applicationContext.getSystemService("accessibility");
        if (am.isEnabled()) {
            AccessibilityEvent ev = AccessibilityEvent.obtain();
            ev.setEventType(16384);
            ev.getText().add(what);
            am.sendAccessibilityEvent(ev);
        }
    }

    public static int getOffsetColor(int color1, int color2, float offset, float alpha) {
        int rF = Color.red(color2);
        int gF = Color.green(color2);
        int bF = Color.blue(color2);
        int aF = Color.alpha(color2);
        int rS = Color.red(color1);
        int gS = Color.green(color1);
        int bS = Color.blue(color1);
        int aS = Color.alpha(color1);
        return Color.argb((int) ((aS + ((aF - aS) * offset)) * alpha), (int) (rS + ((rF - rS) * offset)), (int) (gS + ((gF - gS) * offset)), (int) (bS + ((bF - bS) * offset)));
    }

    public static int indexOfIgnoreCase(String origin, String searchStr) {
        if (searchStr.isEmpty() || origin.isEmpty()) {
            return origin.indexOf(searchStr);
        }
        for (int i = 0; i < origin.length() && searchStr.length() + i <= origin.length(); i++) {
            int j = 0;
            for (int ii = i; ii < origin.length() && j < searchStr.length(); ii++) {
                char c = Character.toLowerCase(origin.charAt(ii));
                char c2 = Character.toLowerCase(searchStr.charAt(j));
                if (c != c2) {
                    break;
                }
                j++;
            }
            if (j == searchStr.length()) {
                return i;
            }
        }
        return -1;
    }

    public static float computePerceivedBrightness(int color) {
        return (((Color.red(color) * 0.2126f) + (Color.green(color) * 0.7152f)) + (Color.blue(color) * 0.0722f)) / 255.0f;
    }

    public static void setLightNavigationBar(Window window, boolean enable) {
        int flags;
        if (Build.VERSION.SDK_INT >= 26) {
            View decorView = window.getDecorView();
            int flags2 = decorView.getSystemUiVisibility();
            if (enable) {
                flags = flags2 | 16;
            } else {
                flags = flags2 & (-17);
            }
            decorView.setSystemUiVisibility(flags);
        }
    }

    public static int getVersionCode(Context mContext) {
        try {
            int versionCode = mContext.getPackageManager().getPackageInfo(mContext.getPackageName(), 0).versionCode;
            return versionCode;
        } catch (PackageManager.NameNotFoundException e) {
            e.printStackTrace();
            return 0;
        }
    }

    public static String getVersionName(Context context) {
        try {
            String verName = context.getPackageManager().getPackageInfo(context.getPackageName(), 0).versionName;
            return verName;
        } catch (PackageManager.NameNotFoundException e) {
            e.printStackTrace();
            return "";
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:44:0x0047 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static byte[] getBlock(long r6, java.io.File r8, int r9) {
        /*
            byte[] r0 = new byte[r9]
            r1 = 0
            r2 = 0
            java.io.RandomAccessFile r3 = new java.io.RandomAccessFile     // Catch: java.lang.Throwable -> L36 java.io.IOException -> L38
            java.lang.String r4 = "r"
            r3.<init>(r8, r4)     // Catch: java.lang.Throwable -> L36 java.io.IOException -> L38
            r1 = r3
            r1.seek(r6)     // Catch: java.lang.Throwable -> L36 java.io.IOException -> L38
            int r3 = r1.read(r0)     // Catch: java.lang.Throwable -> L36 java.io.IOException -> L38
            r4 = -1
            if (r3 != r4) goto L1e
        L18:
            r1.close()     // Catch: java.io.IOException -> L1c
            goto L1d
        L1c:
            r4 = move-exception
        L1d:
            return r2
        L1e:
            if (r3 != r9) goto L28
        L22:
            r1.close()     // Catch: java.io.IOException -> L26
            goto L27
        L26:
            r2 = move-exception
        L27:
            return r0
        L28:
            byte[] r4 = new byte[r3]     // Catch: java.lang.Throwable -> L36 java.io.IOException -> L38
            r5 = 0
            java.lang.System.arraycopy(r0, r5, r4, r5, r3)     // Catch: java.lang.Throwable -> L36 java.io.IOException -> L38
            r1.close()     // Catch: java.io.IOException -> L34
            goto L35
        L34:
            r2 = move-exception
        L35:
            return r4
        L36:
            r2 = move-exception
            goto L45
        L38:
            r3 = move-exception
            r3.printStackTrace()     // Catch: java.lang.Throwable -> L36
            if (r1 == 0) goto L44
            r1.close()     // Catch: java.io.IOException -> L42
        L41:
            goto L44
        L42:
            r3 = move-exception
            goto L41
        L44:
            return r2
        L45:
            if (r1 == 0) goto L4c
            r1.close()     // Catch: java.io.IOException -> L4b
            goto L4c
        L4b:
            r3 = move-exception
        L4c:
            throw r2
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.AndroidUtilities.getBlock(long, java.io.File, int):byte[]");
    }

    public static String getFileMD5(File file) {
        if (!file.isFile()) {
            return null;
        }
        byte[] buffer = new byte[1024];
        try {
            MessageDigest digest = MessageDigest.getInstance("MD5");
            FileInputStream in = new FileInputStream(file);
            while (true) {
                int len = in.read(buffer, 0, 1024);
                if (len != -1) {
                    digest.update(buffer, 0, len);
                } else {
                    in.close();
                    byte[] resultByteArray = digest.digest();
                    return byteArrayToHex(resultByteArray);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static String byteArrayToHex(byte[] byteArray) {
        char[] hexDigits = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
        char[] resultCharArray = new char[byteArray.length * 2];
        int index = 0;
        for (byte b : byteArray) {
            int index2 = index + 1;
            resultCharArray[index] = hexDigits[(b >>> 4) & 15];
            index = index2 + 1;
            resultCharArray[index2] = hexDigits[b & 15];
        }
        return new String(resultCharArray);
    }

    public static boolean checkHasExitsUserOrDeletedEverAndShowDialog(BaseFragment host, String phone) {
        if (phone == null) {
            return false;
        }
        for (int i = 0; i < 3; i++) {
            UserConfig userConfig = UserConfig.getInstance(i);
            if (UserObject.isDeleted(userConfig.getCurrentUser())) {
                AlertsCreator.showSimpleAlert(host, LocaleController.getString("ReminderDeletedEverPleaseUseOtherAccount", mpEIGo.juqQQs.esbSDO.R.string.ReminderDeletedEverPleaseUseOtherAccount));
                return true;
            }
            String userPhone = userConfig.getCurrentUser().phone;
            if (PhoneNumberUtils.compare(phone, userPhone)) {
                if (i == UserConfig.selectedAccount) {
                    AlertsCreator.showSimpleAlert(host, LocaleController.getString("AccountAlreadyLoggedIn", mpEIGo.juqQQs.esbSDO.R.string.AccountAlreadyLoggedIn));
                } else {
                    AlertsCreator.showSimpleAlert(host, LocaleController.getString("ReminderAccountHadExitsAndSwitchAccount", mpEIGo.juqQQs.esbSDO.R.string.ReminderAccountHadExitsAndSwitchAccount));
                }
                return true;
            }
        }
        return false;
    }

    public static boolean checkCamera(Context context) throws CameraAccessException {
        CameraManager manager = (CameraManager) context.getSystemService("camera");
        String[] cameraIds = new String[0];
        try {
            cameraIds = manager.getCameraIdList();
        } catch (Exception e) {
            e.printStackTrace();
        }
        if (cameraIds != null && cameraIds.length > 0) {
            String str = cameraIds[0];
            if (cameraIds[1] != null) {
                return true;
            }
        }
        return false;
    }

    public static boolean isAppOnForeground(Context context) {
        ActivityManager activityManager = (ActivityManager) context.getApplicationContext().getSystemService("activity");
        String packageName = context.getApplicationContext().getPackageName();
        List<ActivityManager.RunningAppProcessInfo> appProcesses = null;
        if (activityManager != null) {
            appProcesses = activityManager.getRunningAppProcesses();
        }
        if (appProcesses == null) {
            return false;
        }
        for (ActivityManager.RunningAppProcessInfo appProcess : appProcesses) {
            if (appProcess.processName.equals(packageName) && appProcess.importance == 100) {
                return true;
            }
        }
        return false;
    }

    public static int getSystemVersion() {
        return Integer.parseInt(Build.VERSION.RELEASE);
    }

    public static void handleKeyboardShelterProblem(EditText editText) {
        handleKeyboardShelterProblem(editText, false);
    }

    public static void handleKeyboardShelterProblem(EditText editText, boolean callSuper) {
        if (editText != null && isEMUI() && Build.VERSION.SDK_INT >= 27) {
            int inputType = editText.getInputType();
            int variation = inputType & 4095;
            boolean passwordInputType = variation == 129;
            boolean webPasswordInputType = variation == 225;
            boolean numberPasswordInputType = variation == 18;
            if (passwordInputType || webPasswordInputType) {
                editText.setInputType(1);
            } else if (numberPasswordInputType) {
                editText.setInputType(2);
            }
            if (passwordInputType || webPasswordInputType || numberPasswordInputType) {
                editText.setTransformationMethod(PasswordTransformationMethod.getInstance());
            }
        }
    }

    public static boolean isMIUI() {
        String manufacturer = Build.MANUFACTURER;
        if ("xiaomi".equalsIgnoreCase(manufacturer)) {
            return true;
        }
        return false;
    }

    public static boolean isEMUI() {
        String manufacturer = Build.MANUFACTURER;
        if ("HUAWEI".equalsIgnoreCase(manufacturer)) {
            return true;
        }
        return false;
    }

    public static boolean isOPPO() {
        String manufacturer = Build.MANUFACTURER;
        if ("OPPO".equalsIgnoreCase(manufacturer)) {
            return true;
        }
        return false;
    }

    public static boolean isVIVO() {
        String manufacturer = Build.MANUFACTURER;
        if ("vivo".equalsIgnoreCase(manufacturer)) {
            return true;
        }
        return false;
    }

    public static int alphaColor(float fraction, int color) {
        int r = (color >> 16) & 255;
        int g = (color >> 8) & 255;
        int b = color & 255;
        return (((int) (256.0f * fraction)) << 24) | (r << 16) | (g << 8) | b;
    }

    public static boolean containsEmoji(CharSequence source) {
        int len = source.length();
        for (int i = 0; i < len; i++) {
            char codePoint = source.charAt(i);
            if (!isEmojiCharacter(codePoint)) {
                return true;
            }
        }
        return false;
    }

    public static boolean isEmojiCharacter(char codePoint) {
        return codePoint == 0 || codePoint == '\t' || codePoint == '\n' || codePoint == '\r' || (codePoint >= ' ' && codePoint <= 55295) || ((codePoint >= 57344 && codePoint <= 65533) || (codePoint >= 0 && codePoint <= 65535));
    }

    public static boolean isScreenOriatationPortrait(Context context) {
        return context.getResources().getConfiguration().orientation == 1;
    }

    public static Bitmap blurBitmap(Context context, Bitmap bitmap) {
        Bitmap outBitmap = Bitmap.createBitmap(bitmap.getWidth(), bitmap.getHeight(), Bitmap.Config.ARGB_8888);
        RenderScript rs = RenderScript.create(context);
        ScriptIntrinsicBlur blurScript = ScriptIntrinsicBlur.create(rs, Element.U8_4(rs));
        Allocation allIn = Allocation.createFromBitmap(rs, bitmap);
        Allocation allOut = Allocation.createFromBitmap(rs, outBitmap);
        blurScript.setRadius(15.0f);
        blurScript.setInput(allIn);
        blurScript.forEach(allOut);
        allOut.copyTo(outBitmap);
        rs.destroy();
        return outBitmap;
    }
}
