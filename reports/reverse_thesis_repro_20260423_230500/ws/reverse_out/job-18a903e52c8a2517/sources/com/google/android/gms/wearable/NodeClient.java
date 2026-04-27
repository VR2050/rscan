package com.google.android.gms.wearable;

import android.app.Activity;
import android.content.Context;
import com.google.android.gms.common.api.Api;
import com.google.android.gms.common.api.GoogleApi;
import com.google.android.gms.tasks.Task;
import com.google.android.gms.wearable.Wearable;
import java.util.List;

/* JADX INFO: loaded from: classes.dex */
public abstract class NodeClient extends GoogleApi<Wearable.WearableOptions> {
    public NodeClient(Context context, GoogleApi.Settings settings) {
        super(context, Wearable.API, (Api.ApiOptions) null, settings);
    }

    public abstract Task<List<Node>> getConnectedNodes();

    public abstract Task<Node> getLocalNode();

    public NodeClient(Activity activity, GoogleApi.Settings settings) {
        super(activity, (Api<Api.ApiOptions>) Wearable.API, (Api.ApiOptions) null, settings);
    }
}
