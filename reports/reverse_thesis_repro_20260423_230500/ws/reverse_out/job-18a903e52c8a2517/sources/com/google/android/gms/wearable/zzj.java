package com.google.android.gms.wearable;

import android.content.Context;
import android.os.Looper;
import com.google.android.gms.common.api.Api;
import com.google.android.gms.common.api.GoogleApiClient;
import com.google.android.gms.common.internal.ClientSettings;
import com.google.android.gms.wearable.Wearable;
import com.google.android.gms.wearable.internal.zzhg;

/* JADX INFO: loaded from: classes.dex */
final class zzj extends Api.AbstractClientBuilder<zzhg, Wearable.WearableOptions> {
    zzj() {
    }

    @Override // com.google.android.gms.common.api.Api.AbstractClientBuilder
    public final /* synthetic */ Api.Client buildClient(Context context, Looper looper, ClientSettings clientSettings, Wearable.WearableOptions wearableOptions, GoogleApiClient.ConnectionCallbacks connectionCallbacks, GoogleApiClient.OnConnectionFailedListener onConnectionFailedListener) {
        if (wearableOptions == null) {
            new Wearable.WearableOptions(new Wearable.WearableOptions.Builder(), null);
        }
        return new zzhg(context, looper, connectionCallbacks, onConnectionFailedListener, clientSettings);
    }
}
