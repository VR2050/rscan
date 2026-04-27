package com.google.android.gms.wearable.internal;

import android.app.Activity;
import android.content.Context;
import com.google.android.gms.common.api.GoogleApi;
import com.google.android.gms.common.internal.PendingResultUtil;
import com.google.android.gms.tasks.Task;
import com.google.android.gms.wearable.Node;
import com.google.android.gms.wearable.NodeApi;
import com.google.android.gms.wearable.NodeClient;
import java.util.List;

/* JADX INFO: loaded from: classes.dex */
public final class zzfl extends NodeClient {
    private final NodeApi zzem;

    public zzfl(Context context, GoogleApi.Settings settings) {
        super(context, settings);
        this.zzem = new zzfg();
    }

    public zzfl(Activity activity, GoogleApi.Settings settings) {
        super(activity, settings);
        this.zzem = new zzfg();
    }

    @Override // com.google.android.gms.wearable.NodeClient
    public final Task<Node> getLocalNode() {
        return PendingResultUtil.toTask(this.zzem.getLocalNode(asGoogleApiClient()), zzfm.zzbx);
    }

    @Override // com.google.android.gms.wearable.NodeClient
    public final Task<List<Node>> getConnectedNodes() {
        return PendingResultUtil.toTask(this.zzem.getConnectedNodes(asGoogleApiClient()), zzfn.zzbx);
    }
}
