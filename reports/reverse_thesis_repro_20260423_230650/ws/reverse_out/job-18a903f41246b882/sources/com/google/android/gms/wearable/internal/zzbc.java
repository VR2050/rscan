package com.google.android.gms.wearable.internal;

import android.os.RemoteException;
import com.google.android.gms.common.api.Api;
import com.google.android.gms.common.api.GoogleApiClient;
import com.google.android.gms.common.api.Result;
import com.google.android.gms.common.api.Status;
import com.google.android.gms.wearable.Channel;

/* JADX INFO: loaded from: classes.dex */
final class zzbc extends zzn<Channel.GetOutputStreamResult> {
    private final /* synthetic */ zzay zzcm;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    zzbc(zzay zzayVar, GoogleApiClient googleApiClient) {
        super(googleApiClient);
        this.zzcm = zzayVar;
    }

    @Override // com.google.android.gms.common.api.internal.BaseImplementation.ApiMethodImpl
    protected final /* synthetic */ void doExecute(Api.AnyClient anyClient) throws RemoteException {
        String str = this.zzcm.zzce;
        zzbr zzbrVar = new zzbr();
        ((zzep) ((zzhg) anyClient).getService()).zzb(new zzgt(this, zzbrVar), zzbrVar, str);
    }

    @Override // com.google.android.gms.common.api.internal.BasePendingResult
    public final /* synthetic */ Result createFailedResult(Status status) {
        return new zzbh(status, null);
    }
}
