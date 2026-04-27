package com.google.android.gms.wearable.internal;

import android.net.Uri;
import android.os.RemoteException;
import com.google.android.gms.common.api.Api;
import com.google.android.gms.common.api.GoogleApiClient;
import com.google.android.gms.common.api.Result;
import com.google.android.gms.common.api.Status;
import com.google.android.gms.wearable.DataApi;

/* JADX INFO: loaded from: classes.dex */
final class zzby extends zzn<DataApi.DataItemResult> {
    private final /* synthetic */ Uri zzco;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    zzby(zzbw zzbwVar, GoogleApiClient googleApiClient, Uri uri) {
        super(googleApiClient);
        this.zzco = uri;
    }

    @Override // com.google.android.gms.common.api.internal.BaseImplementation.ApiMethodImpl
    protected final /* synthetic */ void doExecute(Api.AnyClient anyClient) throws RemoteException {
        ((zzep) ((zzhg) anyClient).getService()).zza(new zzgv(this), this.zzco);
    }

    @Override // com.google.android.gms.common.api.internal.BasePendingResult
    protected final /* synthetic */ Result createFailedResult(Status status) {
        return new zzcg(status, null);
    }
}
