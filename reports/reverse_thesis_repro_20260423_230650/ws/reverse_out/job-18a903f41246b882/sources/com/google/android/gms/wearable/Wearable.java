package com.google.android.gms.wearable;

import android.app.Activity;
import android.content.Context;
import android.os.Looper;
import androidx.core.util.Preconditions;
import com.google.android.gms.common.api.Api;
import com.google.android.gms.common.api.GoogleApi;
import com.google.android.gms.wearable.internal.zzaa;
import com.google.android.gms.wearable.internal.zzaj;
import com.google.android.gms.wearable.internal.zzao;
import com.google.android.gms.wearable.internal.zzbv;
import com.google.android.gms.wearable.internal.zzbw;
import com.google.android.gms.wearable.internal.zzcj;
import com.google.android.gms.wearable.internal.zzeu;
import com.google.android.gms.wearable.internal.zzez;
import com.google.android.gms.wearable.internal.zzfg;
import com.google.android.gms.wearable.internal.zzfl;
import com.google.android.gms.wearable.internal.zzgi;
import com.google.android.gms.wearable.internal.zzhg;
import com.google.android.gms.wearable.internal.zzhq;

/* JADX INFO: loaded from: classes.dex */
public class Wearable {

    @Deprecated
    public static final Api<WearableOptions> API;
    private static final Api.AbstractClientBuilder<zzhg, WearableOptions> CLIENT_BUILDER;

    @Deprecated
    public static final DataApi DataApi = new zzbw();

    @Deprecated
    public static final CapabilityApi CapabilityApi = new com.google.android.gms.wearable.internal.zzo();

    @Deprecated
    public static final MessageApi MessageApi = new zzeu();

    @Deprecated
    public static final NodeApi NodeApi = new zzfg();

    @Deprecated
    public static final ChannelApi ChannelApi = new zzaj();

    @Deprecated
    private static final zzc zzx = new com.google.android.gms.wearable.internal.zzk();

    @Deprecated
    private static final zza zzy = new com.google.android.gms.wearable.internal.zzh();

    @Deprecated
    private static final zzf zzz = new zzbv();

    @Deprecated
    private static final zzi zzaa = new zzgi();

    @Deprecated
    private static final zzu zzab = new zzhq();
    private static final Api.ClientKey<zzhg> CLIENT_KEY = new Api.ClientKey<>();

    private Wearable() {
    }

    public static DataClient getDataClient(Context context) {
        return new zzcj(context, GoogleApi.Settings.DEFAULT_SETTINGS);
    }

    public static final class WearableOptions implements Api.ApiOptions.Optional {
        private final Looper zzac;

        public static class Builder {
            private Looper zzac;

            public WearableOptions build() {
                return new WearableOptions(this, null);
            }

            public Builder setLooper(Looper looper) {
                this.zzac = looper;
                return this;
            }
        }

        private WearableOptions(Builder builder) {
            this.zzac = builder.zzac;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public final GoogleApi.Settings zza() {
            if (this.zzac != null) {
                return new GoogleApi.Settings.Builder().setLooper(this.zzac).build();
            }
            return GoogleApi.Settings.DEFAULT_SETTINGS;
        }

        /* synthetic */ WearableOptions(Builder builder, zzj zzjVar) {
            this(builder);
        }
    }

    public static DataClient getDataClient(Context context, WearableOptions wearableOptions) {
        Preconditions.checkNotNull(wearableOptions, "options must not be null");
        return new zzcj(context, wearableOptions.zza());
    }

    public static DataClient getDataClient(Activity activity) {
        return new zzcj(activity, GoogleApi.Settings.DEFAULT_SETTINGS);
    }

    public static DataClient getDataClient(Activity activity, WearableOptions wearableOptions) {
        Preconditions.checkNotNull(wearableOptions, "options must not be null");
        return new zzcj(activity, wearableOptions.zza());
    }

    public static MessageClient getMessageClient(Context context) {
        return new zzez(context, GoogleApi.Settings.DEFAULT_SETTINGS);
    }

    public static MessageClient getMessageClient(Context context, WearableOptions wearableOptions) {
        Preconditions.checkNotNull(wearableOptions, "options must not be null");
        return new zzez(context, wearableOptions.zza());
    }

    public static MessageClient getMessageClient(Activity activity) {
        return new zzez(activity, GoogleApi.Settings.DEFAULT_SETTINGS);
    }

    public static MessageClient getMessageClient(Activity activity, WearableOptions wearableOptions) {
        Preconditions.checkNotNull(wearableOptions, "options must not be null");
        return new zzez(activity, wearableOptions.zza());
    }

    public static CapabilityClient getCapabilityClient(Context context) {
        return new zzaa(context, GoogleApi.Settings.DEFAULT_SETTINGS);
    }

    public static CapabilityClient getCapabilityClient(Context context, WearableOptions wearableOptions) {
        Preconditions.checkNotNull(wearableOptions, "options must not be null");
        return new zzaa(context, wearableOptions.zza());
    }

    public static CapabilityClient getCapabilityClient(Activity activity) {
        return new zzaa(activity, GoogleApi.Settings.DEFAULT_SETTINGS);
    }

    public static CapabilityClient getCapabilityClient(Activity activity, WearableOptions wearableOptions) {
        Preconditions.checkNotNull(wearableOptions, "options must not be null");
        return new zzaa(activity, wearableOptions.zza());
    }

    public static NodeClient getNodeClient(Context context) {
        return new zzfl(context, GoogleApi.Settings.DEFAULT_SETTINGS);
    }

    public static NodeClient getNodeClient(Context context, WearableOptions wearableOptions) {
        Preconditions.checkNotNull(wearableOptions, "options must not be null");
        return new zzfl(context, wearableOptions.zza());
    }

    public static NodeClient getNodeClient(Activity activity) {
        return new zzfl(activity, GoogleApi.Settings.DEFAULT_SETTINGS);
    }

    public static NodeClient getNodeClient(Activity activity, WearableOptions wearableOptions) {
        Preconditions.checkNotNull(wearableOptions, "options must not be null");
        return new zzfl(activity, wearableOptions.zza());
    }

    public static ChannelClient getChannelClient(Context context) {
        return new zzao(context, GoogleApi.Settings.DEFAULT_SETTINGS);
    }

    public static ChannelClient getChannelClient(Context context, WearableOptions wearableOptions) {
        Preconditions.checkNotNull(wearableOptions, "options must not be null");
        return new zzao(context, wearableOptions.zza());
    }

    public static ChannelClient getChannelClient(Activity activity) {
        return new zzao(activity, GoogleApi.Settings.DEFAULT_SETTINGS);
    }

    public static ChannelClient getChannelClient(Activity activity, WearableOptions wearableOptions) {
        Preconditions.checkNotNull(wearableOptions, "options must not be null");
        return new zzao(activity, wearableOptions.zza());
    }

    /* JADX WARN: Type inference failed for: r0v5, types: [com.google.android.gms.wearable.internal.zzk, com.google.android.gms.wearable.zzc] */
    /* JADX WARN: Type inference failed for: r0v6, types: [com.google.android.gms.wearable.internal.zzh, com.google.android.gms.wearable.zza] */
    /* JADX WARN: Type inference failed for: r0v7, types: [com.google.android.gms.wearable.internal.zzbv, com.google.android.gms.wearable.zzf] */
    /* JADX WARN: Type inference failed for: r0v8, types: [com.google.android.gms.wearable.internal.zzgi, com.google.android.gms.wearable.zzi] */
    /* JADX WARN: Type inference failed for: r0v9, types: [com.google.android.gms.wearable.internal.zzhq, com.google.android.gms.wearable.zzu] */
    static {
        zzj zzjVar = new zzj();
        CLIENT_BUILDER = zzjVar;
        API = new Api<>("Wearable.API", zzjVar, CLIENT_KEY);
    }
}
