package com.google.android.gms.internal.vision;

import java.util.Collections;
import java.util.List;
import java.util.Map;

/* JADX INFO: Add missing generic type declarations: [FieldDescriptorType] */
/* JADX INFO: loaded from: classes.dex */
final class zzer<FieldDescriptorType> extends zzeq<FieldDescriptorType, Object> {
    zzer(int i) {
        super(i, null);
    }

    @Override // com.google.android.gms.internal.vision.zzeq
    public final void zzao() {
        if (!isImmutable()) {
            for (int i = 0; i < zzdl(); i++) {
                Map.Entry<FieldDescriptorType, Object> entryZzan = zzan(i);
                if (((zzcl) entryZzan.getKey()).zzbq()) {
                    entryZzan.setValue(Collections.unmodifiableList((List) entryZzan.getValue()));
                }
            }
            for (Map.Entry<FieldDescriptorType, Object> entry : zzdm()) {
                if (((zzcl) entry.getKey()).zzbq()) {
                    entry.setValue(Collections.unmodifiableList((List) entry.getValue()));
                }
            }
        }
        super.zzao();
    }
}
