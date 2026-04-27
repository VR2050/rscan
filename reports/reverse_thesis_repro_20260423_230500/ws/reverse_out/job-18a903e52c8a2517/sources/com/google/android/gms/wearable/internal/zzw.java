package com.google.android.gms.wearable.internal;

import com.google.android.gms.wearable.CapabilityInfo;
import com.google.android.gms.wearable.Node;
import java.util.Set;

/* JADX INFO: loaded from: classes.dex */
public final class zzw implements CapabilityInfo {
    private final String name;
    private final Set<Node> zzbt;

    private zzw(String str, Set<Node> set) {
        this.name = str;
        this.zzbt = set;
    }

    public zzw(CapabilityInfo capabilityInfo) {
        this(capabilityInfo.getName(), capabilityInfo.getNodes());
    }

    @Override // com.google.android.gms.wearable.CapabilityInfo
    public final String getName() {
        return this.name;
    }

    @Override // com.google.android.gms.wearable.CapabilityInfo
    public final Set<Node> getNodes() {
        return this.zzbt;
    }
}
