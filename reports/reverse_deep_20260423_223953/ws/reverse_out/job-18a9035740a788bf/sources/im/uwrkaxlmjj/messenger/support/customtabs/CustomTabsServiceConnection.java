package im.uwrkaxlmjj.messenger.support.customtabs;

import android.content.ComponentName;
import android.content.ServiceConnection;
import android.os.IBinder;
import im.uwrkaxlmjj.messenger.support.customtabs.ICustomTabsService;

/* JADX INFO: loaded from: classes2.dex */
public abstract class CustomTabsServiceConnection implements ServiceConnection {
    public abstract void onCustomTabsServiceConnected(ComponentName componentName, CustomTabsClient customTabsClient);

    @Override // android.content.ServiceConnection
    public final void onServiceConnected(ComponentName name, IBinder service) {
        onCustomTabsServiceConnected(name, new CustomTabsClient(ICustomTabsService.Stub.asInterface(service), name) { // from class: im.uwrkaxlmjj.messenger.support.customtabs.CustomTabsServiceConnection.1
        });
    }
}
