package com.facebook.imagepipeline.memory;

import Q0.F;
import Q0.G;
import a0.InterfaceC0215a;
import a0.InterfaceC0218d;
import android.util.SparseIntArray;
import com.facebook.imagepipeline.memory.a;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public class d extends a implements InterfaceC0215a {

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private final int[] f6064k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(InterfaceC0218d interfaceC0218d, F f3, G g3) {
        super(interfaceC0218d, f3, g3);
        j.f(interfaceC0218d, "memoryTrimmableRegistry");
        j.f(f3, "poolParams");
        j.f(g3, "poolStatsTracker");
        SparseIntArray sparseIntArray = f3.f2352c;
        if (sparseIntArray != null) {
            this.f6064k = new int[sparseIntArray.size()];
            int size = sparseIntArray.size();
            for (int i3 = 0; i3 < size; i3++) {
                this.f6064k[i3] = sparseIntArray.keyAt(i3);
            }
        } else {
            this.f6064k = new int[0];
        }
        r();
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.facebook.imagepipeline.memory.a
    /* JADX INFO: renamed from: A, reason: merged with bridge method [inline-methods] */
    public void j(byte[] bArr) {
        j.f(bArr, "value");
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.facebook.imagepipeline.memory.a
    /* JADX INFO: renamed from: B, reason: merged with bridge method [inline-methods] */
    public int n(byte[] bArr) {
        j.f(bArr, "value");
        return bArr.length;
    }

    @Override // com.facebook.imagepipeline.memory.a
    protected int m(int i3) {
        if (i3 <= 0) {
            throw new a.b(Integer.valueOf(i3));
        }
        for (int i4 : this.f6064k) {
            if (i4 >= i3) {
                return i4;
            }
        }
        return i3;
    }

    @Override // com.facebook.imagepipeline.memory.a
    protected int o(int i3) {
        return i3;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.facebook.imagepipeline.memory.a
    /* JADX INFO: renamed from: z, reason: merged with bridge method [inline-methods] */
    public byte[] f(int i3) {
        return new byte[i3];
    }
}
