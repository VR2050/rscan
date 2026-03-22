package androidx.media.session;

import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ActivityInfo;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.content.pm.ServiceInfo;
import android.media.session.MediaController;
import android.os.Build;
import android.os.Messenger;
import android.os.RemoteException;
import android.support.v4.media.MediaBrowserCompat;
import android.support.v4.media.session.MediaControllerCompat;
import android.support.v4.media.session.MediaSessionCompat;
import android.view.KeyEvent;
import androidx.annotation.RestrictTo;
import androidx.media.MediaBrowserServiceCompat;
import java.util.HashSet;
import java.util.List;
import p005b.p131d.p132a.p133a.C1499a;

/* loaded from: classes.dex */
public class MediaButtonReceiver extends BroadcastReceiver {
    private static final String TAG = "MediaButtonReceiver";

    public static class MediaButtonConnectionCallback extends MediaBrowserCompat.C0003b {
        private final Context mContext;
        private final Intent mIntent;
        private MediaBrowserCompat mMediaBrowser;
        private final BroadcastReceiver.PendingResult mPendingResult;

        public MediaButtonConnectionCallback(Context context, Intent intent, BroadcastReceiver.PendingResult pendingResult) {
            this.mContext = context;
            this.mIntent = intent;
            this.mPendingResult = pendingResult;
        }

        private void finish() {
            Messenger messenger;
            MediaBrowserCompat.C0005d c0005d = (MediaBrowserCompat.C0005d) this.mMediaBrowser.f1b;
            MediaBrowserCompat.C0009h c0009h = c0005d.f12f;
            if (c0009h != null && (messenger = c0005d.f13g) != null) {
                try {
                    c0009h.m8a(7, null, messenger);
                } catch (RemoteException unused) {
                }
            }
            c0005d.f8b.disconnect();
            this.mPendingResult.finish();
        }

        @Override // android.support.v4.media.MediaBrowserCompat.C0003b
        public void onConnected() {
            Context context;
            MediaSessionCompat.Token token;
            try {
                context = this.mContext;
                MediaBrowserCompat.C0005d c0005d = (MediaBrowserCompat.C0005d) this.mMediaBrowser.f1b;
                if (c0005d.f14h == null) {
                    c0005d.f14h = MediaSessionCompat.Token.m27b(c0005d.f8b.getSessionToken(), null);
                }
                token = c0005d.f14h;
                new HashSet();
            } catch (RemoteException unused) {
            }
            if (token == null) {
                throw new IllegalArgumentException("sessionToken must not be null");
            }
            int i2 = Build.VERSION.SDK_INT;
            MediaControllerCompat.MediaControllerImplApi21 c0020d = i2 >= 24 ? new MediaControllerCompat.C0020d(context, token) : i2 >= 23 ? new MediaControllerCompat.C0019c(context, token) : new MediaControllerCompat.MediaControllerImplApi21(context, token);
            KeyEvent keyEvent = (KeyEvent) this.mIntent.getParcelableExtra("android.intent.extra.KEY_EVENT");
            if (keyEvent == null) {
                throw new IllegalArgumentException("KeyEvent may not be null");
            }
            ((MediaController) c0020d.f40a).dispatchMediaButtonEvent(keyEvent);
            finish();
        }

        @Override // android.support.v4.media.MediaBrowserCompat.C0003b
        public void onConnectionFailed() {
            finish();
        }

        @Override // android.support.v4.media.MediaBrowserCompat.C0003b
        public void onConnectionSuspended() {
            finish();
        }

        public void setMediaBrowser(MediaBrowserCompat mediaBrowserCompat) {
            this.mMediaBrowser = mediaBrowserCompat;
        }
    }

    public static PendingIntent buildMediaButtonPendingIntent(Context context, long j2) {
        ComponentName mediaButtonReceiverComponent = getMediaButtonReceiverComponent(context);
        if (mediaButtonReceiverComponent == null) {
            return null;
        }
        return buildMediaButtonPendingIntent(context, mediaButtonReceiverComponent, j2);
    }

    @RestrictTo({RestrictTo.Scope.LIBRARY})
    public static ComponentName getMediaButtonReceiverComponent(Context context) {
        Intent intent = new Intent("android.intent.action.MEDIA_BUTTON");
        intent.setPackage(context.getPackageName());
        List<ResolveInfo> queryBroadcastReceivers = context.getPackageManager().queryBroadcastReceivers(intent, 0);
        if (queryBroadcastReceivers.size() == 1) {
            ActivityInfo activityInfo = queryBroadcastReceivers.get(0).activityInfo;
            return new ComponentName(activityInfo.packageName, activityInfo.name);
        }
        queryBroadcastReceivers.size();
        return null;
    }

    private static ComponentName getServiceComponentByAction(Context context, String str) {
        PackageManager packageManager = context.getPackageManager();
        Intent intent = new Intent(str);
        intent.setPackage(context.getPackageName());
        List<ResolveInfo> queryIntentServices = packageManager.queryIntentServices(intent, 0);
        if (queryIntentServices.size() == 1) {
            ServiceInfo serviceInfo = queryIntentServices.get(0).serviceInfo;
            return new ComponentName(serviceInfo.packageName, serviceInfo.name);
        }
        if (queryIntentServices.isEmpty()) {
            return null;
        }
        StringBuilder m591M = C1499a.m591M("Expected 1 service that handles ", str, ", found ");
        m591M.append(queryIntentServices.size());
        throw new IllegalStateException(m591M.toString());
    }

    public static KeyEvent handleIntent(MediaSessionCompat mediaSessionCompat, Intent intent) {
        if (mediaSessionCompat == null || intent == null || !"android.intent.action.MEDIA_BUTTON".equals(intent.getAction()) || !intent.hasExtra("android.intent.extra.KEY_EVENT")) {
            return null;
        }
        KeyEvent keyEvent = (KeyEvent) intent.getParcelableExtra("android.intent.extra.KEY_EVENT");
        mediaSessionCompat.f51c.m14a(keyEvent);
        return keyEvent;
    }

    private static void startForegroundService(Context context, Intent intent) {
        if (Build.VERSION.SDK_INT >= 26) {
            context.startForegroundService(intent);
        } else {
            context.startService(intent);
        }
    }

    @Override // android.content.BroadcastReceiver
    public void onReceive(Context context, Intent intent) {
        if (intent == null || !"android.intent.action.MEDIA_BUTTON".equals(intent.getAction()) || !intent.hasExtra("android.intent.extra.KEY_EVENT")) {
            String str = "Ignore unsupported intent: " + intent;
            return;
        }
        ComponentName serviceComponentByAction = getServiceComponentByAction(context, "android.intent.action.MEDIA_BUTTON");
        if (serviceComponentByAction != null) {
            intent.setComponent(serviceComponentByAction);
            startForegroundService(context, intent);
            return;
        }
        ComponentName serviceComponentByAction2 = getServiceComponentByAction(context, MediaBrowserServiceCompat.SERVICE_INTERFACE);
        if (serviceComponentByAction2 == null) {
            throw new IllegalStateException("Could not find any Service that handles android.intent.action.MEDIA_BUTTON or implements a media browser service.");
        }
        BroadcastReceiver.PendingResult goAsync = goAsync();
        Context applicationContext = context.getApplicationContext();
        MediaButtonConnectionCallback mediaButtonConnectionCallback = new MediaButtonConnectionCallback(applicationContext, intent, goAsync);
        MediaBrowserCompat mediaBrowserCompat = new MediaBrowserCompat(applicationContext, serviceComponentByAction2, mediaButtonConnectionCallback, null);
        mediaButtonConnectionCallback.setMediaBrowser(mediaBrowserCompat);
        ((MediaBrowserCompat.C0005d) mediaBrowserCompat.f1b).f8b.connect();
    }

    public static PendingIntent buildMediaButtonPendingIntent(Context context, ComponentName componentName, long j2) {
        if (componentName == null) {
            return null;
        }
        int i2 = j2 == 4 ? 126 : j2 == 2 ? 127 : j2 == 32 ? 87 : j2 == 16 ? 88 : j2 == 1 ? 86 : j2 == 64 ? 90 : j2 == 8 ? 89 : j2 == 512 ? 85 : 0;
        if (i2 == 0) {
            return null;
        }
        Intent intent = new Intent("android.intent.action.MEDIA_BUTTON");
        intent.setComponent(componentName);
        intent.putExtra("android.intent.extra.KEY_EVENT", new KeyEvent(0, i2));
        return PendingIntent.getBroadcast(context, i2, intent, 0);
    }
}
