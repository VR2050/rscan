package com.google.android.gms.location;

import android.app.Activity;
import android.content.Context;
import com.google.android.gms.common.api.Api;
import com.google.android.gms.common.api.GoogleApiClient;
import com.google.android.gms.common.api.Result;
import com.google.android.gms.common.api.internal.BaseImplementation;
import com.google.android.gms.internal.location.zzaz;

/* JADX INFO: loaded from: classes.dex */
public class ActivityRecognition {
    public static final Api<Api.ApiOptions.NoOptions> API;

    @Deprecated
    public static final ActivityRecognitionApi ActivityRecognitionApi;
    private static final Api.AbstractClientBuilder<zzaz, Api.ApiOptions.NoOptions> CLIENT_BUILDER;
    private static final Api.ClientKey<zzaz> CLIENT_KEY = new Api.ClientKey<>();
    public static final String CLIENT_NAME = "activity_recognition";

    public static abstract class zza<R extends Result> extends BaseImplementation.ApiMethodImpl<R, zzaz> {
        public zza(GoogleApiClient googleApiClient) {
            super(ActivityRecognition.API, googleApiClient);
        }
    }

    static {
        com.google.android.gms.location.zza zzaVar = new com.google.android.gms.location.zza();
        CLIENT_BUILDER = zzaVar;
        API = new Api<>("ActivityRecognition.API", zzaVar, CLIENT_KEY);
        ActivityRecognitionApi = new com.google.android.gms.internal.location.zze();
    }

    private ActivityRecognition() {
    }

    public static ActivityRecognitionClient getClient(Activity activity) {
        return new ActivityRecognitionClient(activity);
    }

    public static ActivityRecognitionClient getClient(Context context) {
        return new ActivityRecognitionClient(context);
    }
}
