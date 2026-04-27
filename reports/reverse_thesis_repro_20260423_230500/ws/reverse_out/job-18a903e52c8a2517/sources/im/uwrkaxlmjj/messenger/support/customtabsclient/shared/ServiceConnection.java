package im.uwrkaxlmjj.messenger.support.customtabsclient.shared;

import android.content.ComponentName;
import im.uwrkaxlmjj.messenger.support.customtabs.CustomTabsClient;
import im.uwrkaxlmjj.messenger.support.customtabs.CustomTabsServiceConnection;
import java.lang.ref.WeakReference;

/* JADX INFO: loaded from: classes2.dex */
public class ServiceConnection extends CustomTabsServiceConnection {
    private WeakReference<ServiceConnectionCallback> mConnectionCallback;

    public ServiceConnection(ServiceConnectionCallback connectionCallback) {
        this.mConnectionCallback = new WeakReference<>(connectionCallback);
    }

    @Override // im.uwrkaxlmjj.messenger.support.customtabs.CustomTabsServiceConnection
    public void onCustomTabsServiceConnected(ComponentName name, CustomTabsClient client) {
        ServiceConnectionCallback connectionCallback = this.mConnectionCallback.get();
        if (connectionCallback != null) {
            connectionCallback.onServiceConnected(client);
        }
    }

    @Override // android.content.ServiceConnection
    public void onServiceDisconnected(ComponentName name) {
        ServiceConnectionCallback connectionCallback = this.mConnectionCallback.get();
        if (connectionCallback != null) {
            connectionCallback.onServiceDisconnected();
        }
    }
}
