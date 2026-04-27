package com.google.android.gms.internal.vision;

import java.util.Arrays;
import java.util.Collection;
import java.util.RandomAccess;

/* JADX INFO: loaded from: classes.dex */
final class zzcs extends zzbi<Integer> implements zzcw<Integer>, zzej, RandomAccess {
    private static final zzcs zzlm;
    private int size;
    private int[] zzln;

    static {
        zzcs zzcsVar = new zzcs();
        zzlm = zzcsVar;
        zzcsVar.zzao();
    }

    zzcs() {
        this(new int[10], 0);
    }

    private zzcs(int[] iArr, int i) {
        this.zzln = iArr;
        this.size = i;
    }

    private final void zzi(int i) {
        if (i < 0 || i >= this.size) {
            throw new IndexOutOfBoundsException(zzj(i));
        }
    }

    private final String zzj(int i) {
        int i2 = this.size;
        StringBuilder sb = new StringBuilder(35);
        sb.append("Index:");
        sb.append(i);
        sb.append(", Size:");
        sb.append(i2);
        return sb.toString();
    }

    private final void zzq(int i, int i2) {
        int i3;
        zzap();
        if (i < 0 || i > (i3 = this.size)) {
            throw new IndexOutOfBoundsException(zzj(i));
        }
        int[] iArr = this.zzln;
        if (i3 < iArr.length) {
            System.arraycopy(iArr, i, iArr, i + 1, i3 - i);
        } else {
            int[] iArr2 = new int[((i3 * 3) / 2) + 1];
            System.arraycopy(iArr, 0, iArr2, 0, i);
            System.arraycopy(this.zzln, i, iArr2, i + 1, this.size - i);
            this.zzln = iArr2;
        }
        this.zzln[i] = i2;
        this.size++;
        this.modCount++;
    }

    @Override // com.google.android.gms.internal.vision.zzbi, java.util.AbstractList, java.util.List
    public final /* synthetic */ void add(int i, Object obj) {
        zzq(i, ((Integer) obj).intValue());
    }

    @Override // com.google.android.gms.internal.vision.zzbi, java.util.AbstractCollection, java.util.Collection, java.util.List
    public final boolean addAll(Collection<? extends Integer> collection) {
        zzap();
        zzct.checkNotNull(collection);
        if (!(collection instanceof zzcs)) {
            return super.addAll(collection);
        }
        zzcs zzcsVar = (zzcs) collection;
        int i = zzcsVar.size;
        if (i == 0) {
            return false;
        }
        int i2 = this.size;
        if (Integer.MAX_VALUE - i2 < i) {
            throw new OutOfMemoryError();
        }
        int i3 = i2 + i;
        int[] iArr = this.zzln;
        if (i3 > iArr.length) {
            this.zzln = Arrays.copyOf(iArr, i3);
        }
        System.arraycopy(zzcsVar.zzln, 0, this.zzln, this.size, zzcsVar.size);
        this.size = i3;
        this.modCount++;
        return true;
    }

    @Override // com.google.android.gms.internal.vision.zzbi, java.util.AbstractList, java.util.Collection, java.util.List
    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof zzcs)) {
            return super.equals(obj);
        }
        zzcs zzcsVar = (zzcs) obj;
        if (this.size != zzcsVar.size) {
            return false;
        }
        int[] iArr = zzcsVar.zzln;
        for (int i = 0; i < this.size; i++) {
            if (this.zzln[i] != iArr[i]) {
                return false;
            }
        }
        return true;
    }

    @Override // java.util.AbstractList, java.util.List
    public final /* synthetic */ Object get(int i) {
        return Integer.valueOf(getInt(i));
    }

    public final int getInt(int i) {
        zzi(i);
        return this.zzln[i];
    }

    @Override // com.google.android.gms.internal.vision.zzbi, java.util.AbstractList, java.util.Collection, java.util.List
    public final int hashCode() {
        int i = 1;
        for (int i2 = 0; i2 < this.size; i2++) {
            i = (i * 31) + this.zzln[i2];
        }
        return i;
    }

    @Override // com.google.android.gms.internal.vision.zzbi, java.util.AbstractList, java.util.List
    public final /* synthetic */ Object remove(int i) {
        zzap();
        zzi(i);
        int[] iArr = this.zzln;
        int i2 = iArr[i];
        int i3 = this.size;
        if (i < i3 - 1) {
            System.arraycopy(iArr, i + 1, iArr, i, i3 - i);
        }
        this.size--;
        this.modCount++;
        return Integer.valueOf(i2);
    }

    @Override // com.google.android.gms.internal.vision.zzbi, java.util.AbstractCollection, java.util.Collection, java.util.List
    public final boolean remove(Object obj) {
        zzap();
        for (int i = 0; i < this.size; i++) {
            if (obj.equals(Integer.valueOf(this.zzln[i]))) {
                int[] iArr = this.zzln;
                System.arraycopy(iArr, i + 1, iArr, i, this.size - i);
                this.size--;
                this.modCount++;
                return true;
            }
        }
        return false;
    }

    @Override // java.util.AbstractList
    protected final void removeRange(int i, int i2) {
        zzap();
        if (i2 < i) {
            throw new IndexOutOfBoundsException("toIndex < fromIndex");
        }
        int[] iArr = this.zzln;
        System.arraycopy(iArr, i2, iArr, i, this.size - i2);
        this.size -= i2 - i;
        this.modCount++;
    }

    @Override // com.google.android.gms.internal.vision.zzbi, java.util.AbstractList, java.util.List
    public final /* synthetic */ Object set(int i, Object obj) {
        int iIntValue = ((Integer) obj).intValue();
        zzap();
        zzi(i);
        int[] iArr = this.zzln;
        int i2 = iArr[i];
        iArr[i] = iIntValue;
        return Integer.valueOf(i2);
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.List
    public final int size() {
        return this.size;
    }

    public final void zzae(int i) {
        zzq(this.size, i);
    }

    @Override // com.google.android.gms.internal.vision.zzcw
    public final /* synthetic */ zzcw<Integer> zzk(int i) {
        if (i >= this.size) {
            return new zzcs(Arrays.copyOf(this.zzln, i), this.size);
        }
        throw new IllegalArgumentException();
    }
}
