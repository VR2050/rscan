package im.uwrkaxlmjj.messenger.support.customtabsclient.shared;

import im.uwrkaxlmjj.messenger.support.customtabs.CustomTabsClient;

/* JADX INFO: loaded from: classes2.dex */
public interface ServiceConnectionCallback {
    void onServiceConnected(CustomTabsClient customTabsClient);

    void onServiceDisconnected();
}
