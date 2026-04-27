package com.google.android.gms.internal.vision;

import java.util.Iterator;
import java.util.NoSuchElementException;

/* JADX INFO: loaded from: classes.dex */
final class zzbp implements Iterator {
    private final int limit;
    private int position = 0;
    private final /* synthetic */ zzbo zzgw;

    zzbp(zzbo zzboVar) {
        this.zzgw = zzboVar;
        this.limit = this.zzgw.size();
    }

    private final byte nextByte() {
        try {
            zzbo zzboVar = this.zzgw;
            int i = this.position;
            this.position = i + 1;
            return zzboVar.zzl(i);
        } catch (IndexOutOfBoundsException e) {
            throw new NoSuchElementException(e.getMessage());
        }
    }

    @Override // java.util.Iterator
    public final boolean hasNext() {
        return this.position < this.limit;
    }

    @Override // java.util.Iterator
    public final /* synthetic */ Object next() {
        return Byte.valueOf(nextByte());
    }

    @Override // java.util.Iterator
    public final void remove() {
        throw new UnsupportedOperationException();
    }
}
