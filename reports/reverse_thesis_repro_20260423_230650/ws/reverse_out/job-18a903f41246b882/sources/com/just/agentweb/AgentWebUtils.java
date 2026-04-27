package com.just.agentweb;

import android.app.Activity;
import android.content.ContentUris;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.database.Cursor;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.net.Uri;
import android.os.Build;
import android.os.Environment;
import android.os.Handler;
import android.os.Looper;
import android.os.StatFs;
import android.provider.DocumentsContract;
import android.provider.MediaStore;
import android.text.SpannableString;
import android.text.TextUtils;
import android.text.style.ForegroundColorSpan;
import android.util.Log;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewParent;
import android.webkit.ValueCallback;
import android.webkit.WebChromeClient;
import android.webkit.WebView;
import android.widget.Toast;
import androidx.core.app.AppOpsManagerCompat;
import androidx.core.content.ContextCompat;
import androidx.core.content.FileProvider;
import androidx.core.os.EnvironmentCompat;
import androidx.loader.content.CursorLoader;
import com.google.android.exoplayer2.text.ttml.TtmlNode;
import com.google.android.material.snackbar.Snackbar;
import java.io.Closeable;
import java.io.File;
import java.io.IOException;
import java.lang.ref.WeakReference;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.xmlpull.v1.XmlPullParserException;

/* JADX INFO: loaded from: classes3.dex */
public class AgentWebUtils {
    private static final String TAG = AgentWebUtils.class.getSimpleName();
    private static Handler mHandler = null;
    private static Toast mToast = null;
    private static WeakReference<Snackbar> snackbarWeakReference;

    private AgentWebUtils() {
        throw new UnsupportedOperationException("u can't init me");
    }

    public static int dp2px(Context context, float dipValue) {
        float scale = context.getResources().getDisplayMetrics().density;
        return (int) ((dipValue * scale) + 0.5f);
    }

    static final void clearWebView(WebView m) {
        if (m == null || Looper.myLooper() != Looper.getMainLooper()) {
            return;
        }
        m.loadUrl("about:blank");
        m.stopLoading();
        if (m.getHandler() != null) {
            m.getHandler().removeCallbacksAndMessages(null);
        }
        m.removeAllViews();
        ViewGroup mViewGroup = (ViewGroup) m.getParent();
        if (mViewGroup != null) {
            mViewGroup.removeView(m);
        }
        m.setWebChromeClient(null);
        m.setWebViewClient(null);
        m.setTag(null);
        m.clearHistory();
        m.destroy();
    }

    public static String getAgentWebFilePath(Context context) {
        if (!TextUtils.isEmpty(AgentWebConfig.AGENTWEB_FILE_PATH)) {
            return AgentWebConfig.AGENTWEB_FILE_PATH;
        }
        String dir = getDiskExternalCacheDir(context);
        File mFile = new File(dir, "agentweb-cache");
        try {
            if (!mFile.exists()) {
                mFile.mkdirs();
            }
        } catch (Throwable th) {
            LogUtils.i(TAG, "create dir exception");
        }
        LogUtils.i(TAG, "path:" + mFile.getAbsolutePath() + "  path:" + mFile.getPath());
        String absolutePath = mFile.getAbsolutePath();
        AgentWebConfig.AGENTWEB_FILE_PATH = absolutePath;
        return absolutePath;
    }

    public static File createFileByName(Context context, String name, boolean cover) throws IOException {
        String path = getAgentWebFilePath(context);
        if (TextUtils.isEmpty(path)) {
            return null;
        }
        File mFile = new File(path, name);
        if (mFile.exists()) {
            if (cover) {
                mFile.delete();
                mFile.createNewFile();
            }
        } else {
            mFile.createNewFile();
        }
        return mFile;
    }

    /*  JADX ERROR: UnsupportedOperationException in pass: RegionMakerVisitor
        java.lang.UnsupportedOperationException
        	at java.base/java.util.Collections$UnmodifiableCollection.add(Collections.java:1095)
        	at jadx.core.dex.visitors.regions.maker.SwitchRegionMaker$1.leaveRegion(SwitchRegionMaker.java:390)
        	at jadx.core.dex.visitors.regions.DepthRegionTraversal.traverseInternal(DepthRegionTraversal.java:70)
        	at jadx.core.dex.visitors.regions.DepthRegionTraversal.lambda$traverseInternal$0(DepthRegionTraversal.java:68)
        	at java.base/java.util.ArrayList.forEach(ArrayList.java:1612)
        	at jadx.core.dex.visitors.regions.DepthRegionTraversal.traverseInternal(DepthRegionTraversal.java:68)
        	at jadx.core.dex.visitors.regions.DepthRegionTraversal.traverse(DepthRegionTraversal.java:23)
        	at jadx.core.dex.visitors.regions.maker.SwitchRegionMaker.insertBreaksForCase(SwitchRegionMaker.java:370)
        	at jadx.core.dex.visitors.regions.maker.SwitchRegionMaker.insertBreaks(SwitchRegionMaker.java:85)
        	at jadx.core.dex.visitors.regions.PostProcessRegions.leaveRegion(PostProcessRegions.java:33)
        	at jadx.core.dex.visitors.regions.DepthRegionTraversal.traverseInternal(DepthRegionTraversal.java:70)
        	at jadx.core.dex.visitors.regions.DepthRegionTraversal.lambda$traverseInternal$0(DepthRegionTraversal.java:68)
        	at java.base/java.util.ArrayList.forEach(ArrayList.java:1612)
        	at jadx.core.dex.visitors.regions.DepthRegionTraversal.traverseInternal(DepthRegionTraversal.java:68)
        	at jadx.core.dex.visitors.regions.DepthRegionTraversal.lambda$traverseInternal$0(DepthRegionTraversal.java:68)
        	at java.base/java.util.ArrayList.forEach(ArrayList.java:1612)
        	at java.base/java.util.Collections$UnmodifiableCollection.forEach(Collections.java:1120)
        	at jadx.core.dex.visitors.regions.DepthRegionTraversal.traverseInternal(DepthRegionTraversal.java:68)
        	at jadx.core.dex.visitors.regions.DepthRegionTraversal.lambda$traverseInternal$0(DepthRegionTraversal.java:68)
        	at java.base/java.util.ArrayList.forEach(ArrayList.java:1612)
        	at jadx.core.dex.visitors.regions.DepthRegionTraversal.traverseInternal(DepthRegionTraversal.java:68)
        	at jadx.core.dex.visitors.regions.DepthRegionTraversal.lambda$traverseInternal$0(DepthRegionTraversal.java:68)
        	at java.base/java.util.ArrayList.forEach(ArrayList.java:1612)
        	at java.base/java.util.Collections$UnmodifiableCollection.forEach(Collections.java:1120)
        	at jadx.core.dex.visitors.regions.DepthRegionTraversal.traverseInternal(DepthRegionTraversal.java:68)
        	at jadx.core.dex.visitors.regions.DepthRegionTraversal.lambda$traverseInternal$0(DepthRegionTraversal.java:68)
        	at java.base/java.util.ArrayList.forEach(ArrayList.java:1612)
        	at jadx.core.dex.visitors.regions.DepthRegionTraversal.traverseInternal(DepthRegionTraversal.java:68)
        	at jadx.core.dex.visitors.regions.DepthRegionTraversal.traverse(DepthRegionTraversal.java:19)
        	at jadx.core.dex.visitors.regions.PostProcessRegions.process(PostProcessRegions.java:23)
        	at jadx.core.dex.visitors.regions.RegionMakerVisitor.visit(RegionMakerVisitor.java:31)
        */
    public static int checkNetworkType(android.content.Context r6) {
        /*
            r0 = 0
            java.lang.String r1 = "connectivity"
            java.lang.Object r1 = r6.getSystemService(r1)
            android.net.ConnectivityManager r1 = (android.net.ConnectivityManager) r1
            android.net.NetworkInfo r2 = r1.getActiveNetworkInfo()
            if (r2 != 0) goto L10
            return r0
        L10:
            int r3 = r2.getType()
            if (r3 == 0) goto L22
            r4 = 1
            if (r3 == r4) goto L21
            r5 = 6
            if (r3 == r5) goto L21
            r5 = 9
            if (r3 == r5) goto L21
            return r0
        L21:
            return r4
        L22:
            int r3 = r2.getSubtype()
            switch(r3) {
                case 1: goto L31;
                case 2: goto L31;
                case 3: goto L2f;
                case 4: goto L2f;
                case 5: goto L2f;
                case 6: goto L2f;
                default: goto L29;
            }
        L29:
            switch(r3) {
                case 12: goto L2f;
                case 13: goto L2d;
                case 14: goto L2d;
                case 15: goto L2d;
                default: goto L2c;
            }
        L2c:
            return r0
        L2d:
            r3 = 2
            return r3
        L2f:
            r3 = 3
            return r3
        L31:
            r3 = 4
            return r3
        */
        throw new UnsupportedOperationException("Method not decompiled: com.just.agentweb.AgentWebUtils.checkNetworkType(android.content.Context):int");
    }

    public static long getAvailableStorage() {
        try {
            StatFs stat = new StatFs(Environment.getExternalStorageDirectory().toString());
            if (Build.VERSION.SDK_INT >= 18) {
                return stat.getAvailableBlocksLong() * stat.getBlockSizeLong();
            }
            return ((long) stat.getAvailableBlocks()) * ((long) stat.getBlockSize());
        } catch (RuntimeException e) {
            return 0L;
        }
    }

    public static Uri getUriFromFile(Context context, File file) throws XmlPullParserException, IOException {
        if (Build.VERSION.SDK_INT >= 24) {
            Uri uri = getUriFromFileForN(context, file);
            return uri;
        }
        Uri uri2 = Uri.fromFile(file);
        return uri2;
    }

    static Uri getUriFromFileForN(Context context, File file) throws XmlPullParserException, IOException {
        Uri fileUri = FileProvider.getUriForFile(context, context.getPackageName() + ".AgentWebFileProvider", file);
        return fileUri;
    }

    static void setIntentDataAndType(Context context, Intent intent, String type, File file, boolean writeAble) {
        if (Build.VERSION.SDK_INT >= 24) {
            intent.setDataAndType(getUriFromFile(context, file), type);
            intent.addFlags(1);
            if (writeAble) {
                intent.addFlags(2);
                return;
            }
            return;
        }
        intent.setDataAndType(Uri.fromFile(file), type);
    }

    static void setIntentData(Context context, Intent intent, File file, boolean writeAble) {
        if (Build.VERSION.SDK_INT >= 24) {
            intent.setData(getUriFromFile(context, file));
            intent.addFlags(1);
            if (writeAble) {
                intent.addFlags(2);
                return;
            }
            return;
        }
        intent.setData(Uri.fromFile(file));
    }

    static String getDiskExternalCacheDir(Context context) {
        File mFile = context.getExternalCacheDir();
        if ("mounted".equals(EnvironmentCompat.getStorageState(mFile))) {
            return mFile.getAbsolutePath();
        }
        return null;
    }

    static void grantPermissions(Context context, Intent intent, Uri uri, boolean writeAble) {
        int flag = 1;
        if (writeAble) {
            flag = 1 | 2;
        }
        intent.addFlags(flag);
        List<ResolveInfo> resInfoList = context.getPackageManager().queryIntentActivities(intent, 65536);
        for (ResolveInfo resolveInfo : resInfoList) {
            String packageName = resolveInfo.activityInfo.packageName;
            context.grantUriPermission(packageName, uri, flag);
        }
    }

    private static String getMIMEType(File f) {
        String fName = f.getName();
        String end = fName.substring(fName.lastIndexOf(".") + 1, fName.length()).toLowerCase();
        if (end.equals("pdf")) {
            return "application/pdf";
        }
        if (end.equals("m4a") || end.equals("mp3") || end.equals("mid") || end.equals("xmf") || end.equals("ogg") || end.equals("wav")) {
            return "audio/*";
        }
        if (end.equals("3gp") || end.equals("mp4")) {
            return "video/*";
        }
        if (end.equals("jpg") || end.equals("gif") || end.equals("png") || end.equals("jpeg") || end.equals("bmp")) {
            return "image/*";
        }
        if (end.equals("apk")) {
            return "application/vnd.android.package-archive";
        }
        if (end.equals("pptx") || end.equals("ppt")) {
            return "application/vnd.ms-powerpoint";
        }
        if (end.equals("docx") || end.equals("doc")) {
            return "application/vnd.ms-word";
        }
        if (end.equals("xlsx") || end.equals("xls")) {
            return "application/vnd.ms-excel";
        }
        return "*/*";
    }

    static void show(View parent, CharSequence text, int duration, int textColor, int bgColor, CharSequence actionText, int actionTextColor, View.OnClickListener listener) {
        SpannableString spannableString = new SpannableString(text);
        ForegroundColorSpan colorSpan = new ForegroundColorSpan(textColor);
        spannableString.setSpan(colorSpan, 0, spannableString.length(), 33);
        WeakReference<Snackbar> weakReference = new WeakReference<>(Snackbar.make(parent, spannableString, duration));
        snackbarWeakReference = weakReference;
        Snackbar snackbar = weakReference.get();
        View view = snackbar.getView();
        view.setBackgroundColor(bgColor);
        if (actionText != null && actionText.length() > 0 && listener != null) {
            snackbar.setActionTextColor(actionTextColor);
            snackbar.setAction(actionText, listener);
        }
        snackbar.show();
    }

    static void dismiss() {
        WeakReference<Snackbar> weakReference = snackbarWeakReference;
        if (weakReference != null && weakReference.get() != null) {
            snackbarWeakReference.get().dismiss();
            snackbarWeakReference = null;
        }
    }

    public static boolean checkWifi(Context context) {
        NetworkInfo info;
        ConnectivityManager connectivity = (ConnectivityManager) context.getSystemService("connectivity");
        return connectivity != null && (info = connectivity.getActiveNetworkInfo()) != null && info.isConnected() && info.getType() == 1;
    }

    public static boolean checkNetwork(Context context) {
        NetworkInfo info;
        ConnectivityManager connectivity = (ConnectivityManager) context.getSystemService("connectivity");
        return (connectivity == null || (info = connectivity.getActiveNetworkInfo()) == null || !info.isConnected()) ? false : true;
    }

    static boolean isOverriedMethod(Object currentObject, String methodName, String method, Class... clazzs) {
        LogUtils.i(TAG, "  methodName:" + methodName + "   method:" + method);
        boolean tag = false;
        if (currentObject == null) {
            return false;
        }
        try {
            Method mMethod = currentObject.getClass().getMethod(methodName, clazzs);
            String gStr = mMethod.toGenericString();
            tag = !gStr.contains(method);
        } catch (Exception igonre) {
            if (LogUtils.isDebug()) {
                igonre.printStackTrace();
            }
        }
        LogUtils.i(TAG, "isOverriedMethod:" + tag);
        return tag;
    }

    static Method isExistMethod(Object o, String methodName, Class... clazzs) {
        if (o == null) {
            return null;
        }
        try {
            Method mMethod = o.getClass().getDeclaredMethod(methodName, clazzs);
            mMethod.setAccessible(true);
            return mMethod;
        } catch (Throwable th) {
            return null;
        }
    }

    static void clearAgentWebCache(Context context) {
        try {
            clearCacheFolder(new File(getAgentWebFilePath(context)), 0);
        } catch (Throwable throwable) {
            if (LogUtils.isDebug()) {
                throwable.printStackTrace();
            }
        }
    }

    static void clearWebViewAllCache(Context context, WebView webView) {
        try {
            AgentWebConfig.removeAllCookies(null);
            webView.getSettings().setCacheMode(2);
            context.deleteDatabase("webviewCache.db");
            context.deleteDatabase("webview.db");
            webView.clearCache(true);
            webView.clearHistory();
            webView.clearFormData();
            clearCacheFolder(new File(AgentWebConfig.getCachePath(context)), 0);
        } catch (Exception ignore) {
            if (AgentWebConfig.DEBUG) {
                ignore.printStackTrace();
            }
        }
    }

    static void clearWebViewAllCache(Context context) {
        try {
            clearWebViewAllCache(context, new LollipopFixedWebView(context.getApplicationContext()));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    static int clearCacheFolder(File dir, int numDays) {
        int deletedFiles = 0;
        if (dir != null) {
            Log.i("Info", "dir:" + dir.getAbsolutePath());
        }
        if (dir != null && dir.isDirectory()) {
            try {
                for (File child : dir.listFiles()) {
                    if (child.isDirectory()) {
                        deletedFiles += clearCacheFolder(child, numDays);
                    }
                    if (child.lastModified() < new Date().getTime() - (((long) numDays) * 86400000)) {
                        Log.i(TAG, "file name:" + child.getName());
                        if (child.delete()) {
                            deletedFiles++;
                        }
                    }
                }
            } catch (Exception e) {
                Log.e("Info", String.format("Failed to clean the cache, result %s", e.getMessage()));
            }
        }
        return deletedFiles;
    }

    static void clearCache(Context context, int numDays) {
        Log.i("Info", String.format("Starting cache prune, deleting files older than %d days", Integer.valueOf(numDays)));
        int numDeletedFiles = clearCacheFolder(context.getCacheDir(), numDays);
        Log.i("Info", String.format("Cache pruning completed, %d files deleted", Integer.valueOf(numDeletedFiles)));
    }

    public static String[] uriToPath(Activity activity, Uri[] uris) {
        if (activity == null || uris == null || uris.length == 0) {
            return null;
        }
        try {
            String[] paths = new String[uris.length];
            int i = 0;
            int length = uris.length;
            int i2 = 0;
            while (i2 < length) {
                Uri mUri = uris[i2];
                int i3 = i + 1;
                paths[i] = Build.VERSION.SDK_INT > 18 ? getFileAbsolutePath(activity, mUri) : getRealPathBelowVersion(activity, mUri);
                i2++;
                i = i3;
            }
            return paths;
        } catch (Throwable throwable) {
            if (LogUtils.isDebug()) {
                throwable.printStackTrace();
            }
            return null;
        }
    }

    private static String getRealPathBelowVersion(Context context, Uri uri) {
        String filePath = null;
        LogUtils.i(TAG, "method -> getRealPathBelowVersion " + uri + "   path:" + uri.getPath() + "    getAuthority:" + uri.getAuthority());
        String[] projection = {"_data"};
        CursorLoader loader = new CursorLoader(context, uri, projection, null, null, null);
        Cursor cursor = loader.loadInBackground();
        if (cursor != null) {
            cursor.moveToFirst();
            filePath = cursor.getString(cursor.getColumnIndex(projection[0]));
            cursor.close();
        }
        if (filePath == null) {
            String filePath2 = uri.getPath();
            return filePath2;
        }
        return filePath;
    }

    public static File createImageFile(Context context) {
        try {
            String timeStamp = new SimpleDateFormat("yyyyMMddHHmmss", Locale.getDefault()).format(new Date());
            String imageName = String.format("aw_%s.jpg", timeStamp);
            File mFile = createFileByName(context, imageName, true);
            return mFile;
        } catch (Throwable e) {
            e.printStackTrace();
            return null;
        }
    }

    static File createVideoFile(Context context) {
        try {
            String timeStamp = new SimpleDateFormat("yyyyMMddHHmmss", Locale.getDefault()).format(new Date());
            String imageName = String.format("aw_%s.mp4", timeStamp);
            File mFile = createFileByName(context, imageName, true);
            return mFile;
        } catch (Throwable e) {
            e.printStackTrace();
            return null;
        }
    }

    public static void closeIO(Closeable closeable) {
        if (closeable != null) {
            try {
                closeable.close();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    static String getFileAbsolutePath(Activity context, Uri fileUri) {
        if (context == null || fileUri == null) {
            return null;
        }
        if (Build.VERSION.SDK_INT >= 19 && DocumentsContract.isDocumentUri(context, fileUri)) {
            if (isExternalStorageDocument(fileUri)) {
                String docId = DocumentsContract.getDocumentId(fileUri);
                String[] split = docId.split(com.king.zxing.util.LogUtils.COLON);
                if ("primary".equalsIgnoreCase(split[0])) {
                    return Environment.getExternalStorageDirectory() + "/" + split[1];
                }
            } else {
                if (isDownloadsDocument(fileUri)) {
                    String id = DocumentsContract.getDocumentId(fileUri);
                    Uri contentUri = ContentUris.withAppendedId(Uri.parse("content://downloads/public_downloads"), Long.valueOf(id).longValue());
                    return getDataColumn(context, contentUri, null, null);
                }
                if (isMediaDocument(fileUri)) {
                    String docId2 = DocumentsContract.getDocumentId(fileUri);
                    String[] split2 = docId2.split(com.king.zxing.util.LogUtils.COLON);
                    String type = split2[0];
                    Uri contentUri2 = null;
                    if (TtmlNode.TAG_IMAGE.equals(type)) {
                        contentUri2 = MediaStore.Images.Media.EXTERNAL_CONTENT_URI;
                    } else if ("video".equals(type)) {
                        contentUri2 = MediaStore.Video.Media.EXTERNAL_CONTENT_URI;
                    } else if ("audio".equals(type)) {
                        contentUri2 = MediaStore.Audio.Media.EXTERNAL_CONTENT_URI;
                    }
                    String[] selectionArgs = {split2[1]};
                    return getDataColumn(context, contentUri2, "_id=?", selectionArgs);
                }
            }
        } else {
            if (fileUri.getAuthority().equalsIgnoreCase(context.getPackageName() + ".AgentWebFileProvider")) {
                String path = fileUri.getPath();
                int index = path.lastIndexOf("/");
                return getAgentWebFilePath(context) + File.separator + path.substring(index + 1, path.length());
            }
            if ("content".equalsIgnoreCase(fileUri.getScheme())) {
                if (isGooglePhotosUri(fileUri)) {
                    return fileUri.getLastPathSegment();
                }
                return getDataColumn(context, fileUri, null, null);
            }
            if ("file".equalsIgnoreCase(fileUri.getScheme())) {
                return fileUri.getPath();
            }
        }
        return null;
    }

    static String getDataColumn(Context context, Uri uri, String selection, String[] selectionArgs) {
        Cursor cursor = null;
        String[] projection = {"_data"};
        try {
            cursor = context.getContentResolver().query(uri, projection, selection, selectionArgs, null);
            if (cursor != null && cursor.moveToFirst()) {
                int index = cursor.getColumnIndexOrThrow("_data");
                return cursor.getString(index);
            }
            if (cursor != null) {
                cursor.close();
                return null;
            }
            return null;
        } finally {
            if (cursor != null) {
                cursor.close();
            }
        }
    }

    static boolean isExternalStorageDocument(Uri uri) {
        return "com.android.externalstorage.documents".equals(uri.getAuthority());
    }

    static boolean isDownloadsDocument(Uri uri) {
        return "com.android.providers.downloads.documents".equals(uri.getAuthority());
    }

    static boolean isMediaDocument(Uri uri) {
        return "com.android.providers.media.documents".equals(uri.getAuthority());
    }

    static boolean isGooglePhotosUri(Uri uri) {
        return "com.google.android.apps.photos.content".equals(uri.getAuthority());
    }

    static Intent getInstallApkIntentCompat(Context context, File file) {
        Intent mIntent = new Intent().setAction("android.intent.action.VIEW");
        setIntentDataAndType(context, mIntent, "application/vnd.android.package-archive", file, false);
        return mIntent;
    }

    public static Intent getCommonFileIntentCompat(Context context, File file) {
        Intent mIntent = new Intent().setAction("android.intent.action.VIEW");
        setIntentDataAndType(context, mIntent, getMIMEType(file), file, false);
        return mIntent;
    }

    static Intent getIntentCaptureCompat(Context context, File file) throws XmlPullParserException, IOException {
        Intent mIntent = new Intent("android.media.action.IMAGE_CAPTURE");
        Uri mUri = getUriFromFile(context, file);
        mIntent.addCategory("android.intent.category.DEFAULT");
        mIntent.putExtra("output", mUri);
        return mIntent;
    }

    static Intent getIntentVideoCompat(Context context, File file) throws XmlPullParserException, IOException {
        Intent mIntent = new Intent("android.media.action.VIDEO_CAPTURE");
        Uri mUri = getUriFromFile(context, file);
        mIntent.addCategory("android.intent.category.DEFAULT");
        mIntent.putExtra("output", mUri);
        return mIntent;
    }

    static boolean isJson(String target) {
        if (TextUtils.isEmpty(target)) {
            return false;
        }
        try {
            if (target.startsWith("[")) {
                new JSONArray(target);
            } else {
                new JSONObject(target);
            }
            return true;
        } catch (JSONException e) {
            return false;
        }
    }

    public static boolean isUIThread() {
        return Looper.myLooper() == Looper.getMainLooper();
    }

    static boolean isEmptyCollection(Collection collection) {
        return collection == null || collection.isEmpty();
    }

    static boolean isEmptyMap(Map map) {
        return map == null || map.isEmpty();
    }

    static void toastShowShort(Context context, String msg) {
        Toast toast = mToast;
        if (toast == null) {
            mToast = Toast.makeText(context.getApplicationContext(), msg, 0);
        } else {
            toast.setText(msg);
        }
        mToast.show();
    }

    @Deprecated
    static void getUIControllerAndShowMessage(Activity activity, String message, String from) {
        if (activity == null || activity.isFinishing()) {
            return;
        }
        WebParentLayout mWebParentLayout = (WebParentLayout) activity.findViewById(R.id.web_parent_layout_id);
        AbsAgentWebUIController mAgentWebUIController = mWebParentLayout.provide();
        if (mAgentWebUIController != null) {
            mAgentWebUIController.onShowMessage(message, from);
        }
    }

    public static boolean hasPermission(Context context, String... permissions) {
        return hasPermission(context, (List<String>) Arrays.asList(permissions));
    }

    public static boolean hasPermission(Context context, List<String> permissions) {
        if (Build.VERSION.SDK_INT < 23) {
            return true;
        }
        for (String permission : permissions) {
            int result = ContextCompat.checkSelfPermission(context, permission);
            if (result == -1) {
                return false;
            }
            String op = AppOpsManagerCompat.permissionToOp(permission);
            if (!TextUtils.isEmpty(op)) {
                int result2 = AppOpsManagerCompat.noteProxyOp(context, op, context.getPackageName());
                if (result2 != 0) {
                    return false;
                }
            }
        }
        return true;
    }

    public static List<String> getDeniedPermissions(Activity activity, String[] permissions) {
        if (permissions == null || permissions.length == 0) {
            return null;
        }
        List<String> deniedPermissions = new ArrayList<>(permissions.length);
        for (int i = 0; i < permissions.length; i++) {
            if (!hasPermission(activity, permissions[i])) {
                deniedPermissions.add(permissions[i]);
            }
        }
        return deniedPermissions;
    }

    public static AbsAgentWebUIController getAgentWebUIControllerByWebView(WebView webView) {
        WebParentLayout mWebParentLayout = getWebParentLayoutByWebView(webView);
        return mWebParentLayout.provide();
    }

    public static String getApplicationName(Context context) throws PackageManager.NameNotFoundException {
        ApplicationInfo applicationInfo;
        PackageManager packageManager = null;
        try {
            packageManager = context.getApplicationContext().getPackageManager();
            applicationInfo = packageManager.getApplicationInfo(context.getPackageName(), 0);
        } catch (PackageManager.NameNotFoundException e) {
            applicationInfo = null;
        }
        String applicationName = (String) packageManager.getApplicationLabel(applicationInfo);
        return applicationName;
    }

    static WebParentLayout getWebParentLayoutByWebView(WebView webView) {
        if (!(webView.getParent() instanceof ViewGroup)) {
            throw new IllegalStateException("please check webcreator's create method was be called ?");
        }
        ViewGroup mViewGroup = (ViewGroup) webView.getParent();
        while (mViewGroup != null) {
            LogUtils.i(TAG, "ViewGroup:" + mViewGroup);
            if (mViewGroup.getId() == R.id.web_parent_layout_id) {
                WebParentLayout mWebParentLayout = (WebParentLayout) mViewGroup;
                LogUtils.i(TAG, "found WebParentLayout");
                return mWebParentLayout;
            }
            ViewParent mViewParent = mViewGroup.getParent();
            if (mViewParent instanceof ViewGroup) {
                mViewGroup = (ViewGroup) mViewParent;
            } else {
                mViewGroup = null;
            }
        }
        throw new IllegalStateException("please check webcreator's create method was be called ?");
    }

    public static void runInUiThread(Runnable runnable) {
        if (mHandler == null) {
            mHandler = new Handler(Looper.getMainLooper());
        }
        mHandler.post(runnable);
    }

    public static boolean showFileChooserCompat(Activity activity, WebView webView, ValueCallback<Uri[]> valueCallbacks, WebChromeClient.FileChooserParams fileChooserParams, PermissionInterceptor permissionInterceptor, ValueCallback valueCallback, String mimeType, Handler.Callback jsChannelCallback) {
        try {
            Object mFileChooser$Builder = Class.forName("com.just.agentweb.filechooser.FileChooser").getDeclaredMethod("newBuilder", Activity.class, WebView.class).invoke(null, activity, webView);
            Class<?> clz = mFileChooser$Builder.getClass();
            if (valueCallbacks != null) {
                Method mMethod = clz.getDeclaredMethod("setUriValueCallbacks", ValueCallback.class);
                mMethod.setAccessible(true);
                mMethod.invoke(mFileChooser$Builder, valueCallbacks);
            }
            if (fileChooserParams != null) {
                Method mMethod2 = clz.getDeclaredMethod("setFileChooserParams", WebChromeClient.FileChooserParams.class);
                mMethod2.setAccessible(true);
                mMethod2.invoke(mFileChooser$Builder, fileChooserParams);
            }
            if (valueCallback != null) {
                Method mMethod3 = clz.getDeclaredMethod("setUriValueCallback", ValueCallback.class);
                mMethod3.setAccessible(true);
                mMethod3.invoke(mFileChooser$Builder, valueCallback);
            }
            if (!TextUtils.isEmpty(mimeType)) {
                Method mMethod4 = clz.getDeclaredMethod("setAcceptType", String.class);
                mMethod4.setAccessible(true);
                mMethod4.invoke(mFileChooser$Builder, mimeType);
            }
            if (jsChannelCallback != null) {
                Method mMethod5 = clz.getDeclaredMethod("setJsChannelCallback", Handler.Callback.class);
                mMethod5.setAccessible(true);
                mMethod5.invoke(mFileChooser$Builder, jsChannelCallback);
            }
            Method mMethod6 = clz.getDeclaredMethod("setPermissionInterceptor", PermissionInterceptor.class);
            mMethod6.setAccessible(true);
            mMethod6.invoke(mFileChooser$Builder, permissionInterceptor);
            Method mMethod7 = clz.getDeclaredMethod("build", new Class[0]);
            mMethod7.setAccessible(true);
            Object mFileChooser = mMethod7.invoke(mFileChooser$Builder, new Object[0]);
            Method mMethod8 = mFileChooser.getClass().getDeclaredMethod("openFileChooser", new Class[0]);
            mMethod8.setAccessible(true);
            mMethod8.invoke(mFileChooser, new Object[0]);
        } catch (Throwable throwable) {
            if (LogUtils.isDebug()) {
                throwable.printStackTrace();
            }
            if (throwable instanceof ClassNotFoundException) {
                LogUtils.e(TAG, "Please check whether compile'com.just.agentweb:filechooser:x.x.x' dependency was added.");
            }
            if (valueCallbacks != null) {
                LogUtils.i(TAG, "onReceiveValue empty");
                return false;
            }
            if (valueCallback != null) {
                valueCallback.onReceiveValue(null);
            }
        }
        return true;
    }

    public static String md5(String str) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            md.update(str.getBytes());
            return new BigInteger(1, md.digest()).toString(16);
        } catch (Exception e) {
            if (LogUtils.isDebug()) {
                e.printStackTrace();
                return "";
            }
            return "";
        }
    }
}
