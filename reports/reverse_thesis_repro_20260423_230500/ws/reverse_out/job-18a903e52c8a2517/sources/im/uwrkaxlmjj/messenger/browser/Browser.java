package im.uwrkaxlmjj.messenger.browser;

import android.app.Activity;
import android.app.PendingIntent;
import android.content.ComponentName;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.pm.ResolveInfo;
import android.graphics.BitmapFactory;
import android.net.Uri;
import android.os.Bundle;
import android.text.TextUtils;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ApplicationLoader;
import im.uwrkaxlmjj.messenger.BuildVars;
import im.uwrkaxlmjj.messenger.CustomTabsCopyReceiver;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.ShareBroadcastReceiver;
import im.uwrkaxlmjj.messenger.SharedConfig;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.messenger.support.customtabs.CustomTabsCallback;
import im.uwrkaxlmjj.messenger.support.customtabs.CustomTabsClient;
import im.uwrkaxlmjj.messenger.support.customtabs.CustomTabsIntent;
import im.uwrkaxlmjj.messenger.support.customtabs.CustomTabsServiceConnection;
import im.uwrkaxlmjj.messenger.support.customtabs.CustomTabsSession;
import im.uwrkaxlmjj.messenger.support.customtabsclient.shared.CustomTabsHelper;
import im.uwrkaxlmjj.messenger.support.customtabsclient.shared.ServiceConnection;
import im.uwrkaxlmjj.messenger.support.customtabsclient.shared.ServiceConnectionCallback;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.LaunchActivity;
import im.uwrkaxlmjj.ui.actionbar.AlertDialog;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import java.lang.ref.WeakReference;
import java.util.List;
import mpEIGo.juqQQs.esbSDO.R;
import org.webrtc.mozi.ProxyInfo;

/* JADX INFO: loaded from: classes2.dex */
public class Browser {
    private static WeakReference<Activity> currentCustomTabsActivity;
    private static CustomTabsClient customTabsClient;
    private static WeakReference<CustomTabsSession> customTabsCurrentSession;
    private static String customTabsPackageToBind;
    private static CustomTabsServiceConnection customTabsServiceConnection;
    private static CustomTabsSession customTabsSession;

    private static CustomTabsSession getCurrentSession() {
        WeakReference<CustomTabsSession> weakReference = customTabsCurrentSession;
        if (weakReference == null) {
            return null;
        }
        return weakReference.get();
    }

    private static void setCurrentSession(CustomTabsSession session) {
        customTabsCurrentSession = new WeakReference<>(session);
    }

    private static CustomTabsSession getSession() {
        CustomTabsClient customTabsClient2 = customTabsClient;
        if (customTabsClient2 == null) {
            customTabsSession = null;
        } else if (customTabsSession == null) {
            CustomTabsSession customTabsSessionNewSession = customTabsClient2.newSession(new NavigationCallback());
            customTabsSession = customTabsSessionNewSession;
            setCurrentSession(customTabsSessionNewSession);
        }
        return customTabsSession;
    }

    public static void bindCustomTabsService(Activity activity) {
        WeakReference<Activity> weakReference = currentCustomTabsActivity;
        Activity currentActivity = weakReference == null ? null : weakReference.get();
        if (currentActivity != null && currentActivity != activity) {
            unbindCustomTabsService(currentActivity);
        }
        if (customTabsClient != null) {
            return;
        }
        currentCustomTabsActivity = new WeakReference<>(activity);
        try {
            if (TextUtils.isEmpty(customTabsPackageToBind)) {
                String packageNameToUse = CustomTabsHelper.getPackageNameToUse(activity);
                customTabsPackageToBind = packageNameToUse;
                if (packageNameToUse == null) {
                    return;
                }
            }
            ServiceConnection serviceConnection = new ServiceConnection(new ServiceConnectionCallback() { // from class: im.uwrkaxlmjj.messenger.browser.Browser.1
                @Override // im.uwrkaxlmjj.messenger.support.customtabsclient.shared.ServiceConnectionCallback
                public void onServiceConnected(CustomTabsClient client) {
                    CustomTabsClient unused = Browser.customTabsClient = client;
                    if (SharedConfig.customTabs && Browser.customTabsClient != null) {
                        try {
                            Browser.customTabsClient.warmup(0L);
                        } catch (Exception e) {
                            FileLog.e(e);
                        }
                    }
                }

                @Override // im.uwrkaxlmjj.messenger.support.customtabsclient.shared.ServiceConnectionCallback
                public void onServiceDisconnected() {
                    CustomTabsClient unused = Browser.customTabsClient = null;
                }
            });
            customTabsServiceConnection = serviceConnection;
            if (!CustomTabsClient.bindCustomTabsService(activity, customTabsPackageToBind, serviceConnection)) {
                customTabsServiceConnection = null;
            }
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    public static void unbindCustomTabsService(Activity activity) {
        if (customTabsServiceConnection == null) {
            return;
        }
        WeakReference<Activity> weakReference = currentCustomTabsActivity;
        Activity currentActivity = weakReference == null ? null : weakReference.get();
        if (currentActivity == activity) {
            currentCustomTabsActivity.clear();
        }
        try {
            activity.unbindService(customTabsServiceConnection);
        } catch (Exception e) {
        }
        customTabsClient = null;
        customTabsSession = null;
    }

    private static class NavigationCallback extends CustomTabsCallback {
        private NavigationCallback() {
        }

        @Override // im.uwrkaxlmjj.messenger.support.customtabs.CustomTabsCallback
        public void onNavigationEvent(int navigationEvent, Bundle extras) {
        }
    }

    public static void openUrl(Context context, String url) {
        if (url == null) {
            return;
        }
        openUrl(context, Uri.parse(url), true);
    }

    public static void openUrl(Context context, Uri uri) {
        openUrl(context, uri, true);
    }

    public static void openUrl(Context context, String url, boolean allowCustom) {
        if (context == null || url == null) {
            return;
        }
        openUrl(context, Uri.parse(url), allowCustom);
    }

    public static void openUrl(Context context, Uri uri, boolean allowCustom) {
        openUrl(context, uri, allowCustom, true);
    }

    public static void openUrl(Context context, String url, boolean allowCustom, boolean tryTelegraph) {
        openUrl(context, Uri.parse(url), allowCustom, tryTelegraph);
    }

    public static void openUrl(final Context context, final Uri uri, final boolean allowCustom, boolean tryTelegraph) {
        String scheme;
        Uri uri2 = uri;
        if (context == null || uri2 == null) {
            return;
        }
        final int currentAccount = UserConfig.selectedAccount;
        boolean[] forceBrowser = {false};
        boolean internalUri = isInternalUri(uri2, forceBrowser);
        if (tryTelegraph) {
            try {
                if (!uri.getHost().toLowerCase().equals("telegra.ph") && !uri.toString().toLowerCase().contains("m12345.com/faq")) {
                }
                final AlertDialog[] progressDialog = {new AlertDialog(context, 3)};
                TLRPC.TL_messages_getWebPagePreview req = new TLRPC.TL_messages_getWebPagePreview();
                req.message = uri.toString();
                final int reqId = ConnectionsManager.getInstance(UserConfig.selectedAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.browser.-$$Lambda$Browser$JXJGgeL8zVAQLwuYevR2BqRgTU8
                    @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                    public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.browser.-$$Lambda$Browser$o3pjOC_OQRHBmvJ6EtZ1VGcSlHg
                            @Override // java.lang.Runnable
                            public final void run() {
                                Browser.lambda$null$0(alertDialogArr, tLObject, i, uri, context, z);
                            }
                        });
                    }
                });
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.browser.-$$Lambda$Browser$KWvhj9hg6McJ4FQ0SezLciqpHUQ
                    @Override // java.lang.Runnable
                    public final void run() {
                        Browser.lambda$openUrl$3(progressDialog, reqId);
                    }
                }, 1000L);
                return;
            } catch (Exception e) {
            }
        }
        try {
            scheme = uri.getScheme() != null ? uri.getScheme().toLowerCase() : "";
            if ("http".equals(scheme) || ProxyInfo.TYPE_HTTPS.equals(scheme)) {
                try {
                    uri2 = uri.normalizeScheme();
                } catch (Exception e2) {
                    FileLog.e(e2);
                }
            }
        } catch (Exception e3) {
            e = e3;
        }
        try {
            String host = uri2.getHost();
            if (allowCustom && SharedConfig.customTabs && !internalUri && !scheme.equals("tel") && host != null && !"www.shareinstall.com.cn".equals(host)) {
                String[] browserPackageNames = null;
                try {
                    Intent browserIntent = new Intent("android.intent.action.VIEW", Uri.parse("http://www.google.com"));
                    List<ResolveInfo> list = context.getPackageManager().queryIntentActivities(browserIntent, 0);
                    if (list != null && !list.isEmpty()) {
                        browserPackageNames = new String[list.size()];
                        for (int a = 0; a < list.size(); a++) {
                            browserPackageNames[a] = list.get(a).activityInfo.packageName;
                            if (BuildVars.LOGS_ENABLED) {
                                FileLog.d("default browser name = " + browserPackageNames[a]);
                            }
                        }
                    }
                } catch (Exception e4) {
                }
                List<ResolveInfo> allActivities = null;
                try {
                    Intent viewIntent = new Intent("android.intent.action.VIEW", uri2);
                    allActivities = context.getPackageManager().queryIntentActivities(viewIntent, 0);
                    if (browserPackageNames != null) {
                        int a2 = 0;
                        while (a2 < allActivities.size()) {
                            int b = 0;
                            while (true) {
                                if (b >= browserPackageNames.length) {
                                    break;
                                }
                                if (!browserPackageNames[b].equals(allActivities.get(a2).activityInfo.packageName)) {
                                    b++;
                                } else {
                                    allActivities.remove(a2);
                                    a2--;
                                    break;
                                }
                            }
                            a2++;
                        }
                    } else {
                        int a3 = 0;
                        while (a3 < allActivities.size()) {
                            if (allActivities.get(a3).activityInfo.packageName.toLowerCase().contains("browser") || allActivities.get(a3).activityInfo.packageName.toLowerCase().contains("chrome")) {
                                allActivities.remove(a3);
                                a3--;
                            }
                            a3++;
                        }
                    }
                    if (BuildVars.LOGS_ENABLED) {
                        for (int a4 = 0; a4 < allActivities.size(); a4++) {
                            FileLog.d("device has " + allActivities.get(a4).activityInfo.packageName + " to open " + uri2.toString());
                        }
                    }
                } catch (Exception e5) {
                }
                if (forceBrowser[0] || allActivities == null || allActivities.isEmpty()) {
                    Intent share = new Intent(ApplicationLoader.applicationContext, (Class<?>) ShareBroadcastReceiver.class);
                    share.setAction("android.intent.action.SEND");
                    PendingIntent copy = PendingIntent.getBroadcast(ApplicationLoader.applicationContext, 0, new Intent(ApplicationLoader.applicationContext, (Class<?>) CustomTabsCopyReceiver.class), 134217728);
                    CustomTabsIntent.Builder builder = new CustomTabsIntent.Builder(getSession());
                    builder.addMenuItem(LocaleController.getString("CopyLink", R.string.CopyLink), copy);
                    builder.setToolbarColor(Theme.getColor(Theme.key_actionBarBrowser));
                    builder.setShowTitle(true);
                    builder.setActionButton(BitmapFactory.decodeResource(context.getResources(), R.drawable.abc_ic_menu_share_mtrl_alpha), LocaleController.getString("ShareFile", R.string.ShareFile), PendingIntent.getBroadcast(ApplicationLoader.applicationContext, 0, share, 0), false);
                    CustomTabsIntent intent = builder.build();
                    intent.setUseNewTask();
                    intent.launchUrl(context, uri2);
                    return;
                }
            }
        } catch (Exception e6) {
            e = e6;
            FileLog.e(e);
        }
        try {
            Intent intent2 = new Intent("android.intent.action.VIEW", uri2);
            if (internalUri) {
                ComponentName componentName = new ComponentName(context.getPackageName(), LaunchActivity.class.getName());
                intent2.setComponent(componentName);
            }
            intent2.putExtra("create_new_tab", true);
            intent2.putExtra("com.android.browser.application_id", context.getPackageName());
            context.startActivity(intent2);
        } catch (Exception e7) {
            FileLog.e(e7);
        }
    }

    static /* synthetic */ void lambda$null$0(AlertDialog[] progressDialog, TLObject response, int currentAccount, Uri finalUri, Context context, boolean allowCustom) {
        try {
            progressDialog[0].dismiss();
        } catch (Throwable th) {
        }
        progressDialog[0] = null;
        boolean ok = false;
        if (response instanceof TLRPC.TL_messageMediaWebPage) {
            TLRPC.TL_messageMediaWebPage webPage = (TLRPC.TL_messageMediaWebPage) response;
            if ((webPage.webpage instanceof TLRPC.TL_webPage) && webPage.webpage.cached_page != null) {
                NotificationCenter.getInstance(currentAccount).postNotificationName(NotificationCenter.openArticle, webPage.webpage, finalUri.toString());
                ok = true;
            }
        }
        if (!ok) {
            openUrl(context, finalUri, allowCustom, false);
        }
    }

    static /* synthetic */ void lambda$openUrl$3(AlertDialog[] progressDialog, final int reqId) {
        if (progressDialog[0] == null) {
            return;
        }
        try {
            progressDialog[0].setOnCancelListener(new DialogInterface.OnCancelListener() { // from class: im.uwrkaxlmjj.messenger.browser.-$$Lambda$Browser$5iJ3XFoEoP0QacWQbyEDKDRi_CM
                @Override // android.content.DialogInterface.OnCancelListener
                public final void onCancel(DialogInterface dialogInterface) {
                    ConnectionsManager.getInstance(UserConfig.selectedAccount).cancelRequest(reqId, true);
                }
            });
            progressDialog[0].show();
        } catch (Exception e) {
        }
    }

    public static boolean isPassportUrl(String url) {
        if (url == null) {
            return false;
        }
        try {
            String url2 = url.toLowerCase();
            if (url2.startsWith("hchat:passport") || url2.startsWith("hchat://passport") || url2.startsWith("hchat:secureid")) {
                return true;
            }
            if (url2.contains("resolve")) {
                if (url2.contains("domain=hchatpassport")) {
                    return true;
                }
            }
        } catch (Throwable th) {
        }
        return false;
    }

    public static boolean isInternalUrl(String url, boolean[] forceBrowser) {
        return isInternalUri(Uri.parse(url), forceBrowser);
    }

    public static boolean isInternalUri(Uri uri, boolean[] forceBrowser) {
        String path;
        String host = uri.getHost();
        String host2 = host != null ? host.toLowerCase() : "";
        if ("hchat".equals(uri.getScheme()) || "www.shareinstall.com.cn".equals(host2)) {
            return true;
        }
        if (!"m12345.com".equals(host2) || (path = uri.getPath()) == null || path.length() <= 1) {
            return false;
        }
        String path2 = path.substring(1).toLowerCase();
        if (!path2.startsWith("blog") && !path2.equals("iv") && !path2.startsWith("faq") && !path2.equals("apps") && !path2.startsWith("s/")) {
            return true;
        }
        if (forceBrowser != null) {
            forceBrowser[0] = true;
        }
        return false;
    }
}
