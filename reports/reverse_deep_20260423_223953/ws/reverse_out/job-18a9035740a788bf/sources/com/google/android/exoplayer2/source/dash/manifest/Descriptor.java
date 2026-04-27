package com.google.android.exoplayer2.source.dash.manifest;

import com.google.android.exoplayer2.util.Util;

/* JADX INFO: loaded from: classes2.dex */
public final class Descriptor {
    public final String id;
    public final String schemeIdUri;
    public final String value;

    public Descriptor(String schemeIdUri, String value, String id) {
        this.schemeIdUri = schemeIdUri;
        this.value = value;
        this.id = id;
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }
        Descriptor other = (Descriptor) obj;
        return Util.areEqual(this.schemeIdUri, other.schemeIdUri) && Util.areEqual(this.value, other.value) && Util.areEqual(this.id, other.id);
    }

    public int hashCode() {
        String str = this.schemeIdUri;
        int result = str != null ? str.hashCode() : 0;
        int i = result * 31;
        String str2 = this.value;
        int result2 = i + (str2 != null ? str2.hashCode() : 0);
        int result3 = result2 * 31;
        String str3 = this.id;
        return result3 + (str3 != null ? str3.hashCode() : 0);
    }
}
