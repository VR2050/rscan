package com.facebook.imagepipeline.memory;

import Q0.F;
import Q0.G;
import Q0.w;
import X.k;
import a0.InterfaceC0218d;
import android.util.SparseIntArray;
import com.facebook.imagepipeline.memory.a;

/* JADX INFO: loaded from: classes.dex */
public abstract class e extends a {

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private final int[] f6065k;

    e(InterfaceC0218d interfaceC0218d, F f3, G g3) {
        super(interfaceC0218d, f3, g3);
        SparseIntArray sparseIntArray = (SparseIntArray) k.g(f3.f2352c);
        this.f6065k = new int[sparseIntArray.size()];
        int i3 = 0;
        while (true) {
            int[] iArr = this.f6065k;
            if (i3 >= iArr.length) {
                r();
                return;
            } else {
                iArr[i3] = sparseIntArray.keyAt(i3);
                i3++;
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.facebook.imagepipeline.memory.a
    /* JADX INFO: renamed from: A, reason: merged with bridge method [inline-methods] */
    public int n(w wVar) {
        k.g(wVar);
        return wVar.i();
    }

    int B() {
        return this.f6065k[0];
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.facebook.imagepipeline.memory.a
    /* JADX INFO: renamed from: C, reason: merged with bridge method [inline-methods] */
    public boolean t(w wVar) {
        k.g(wVar);
        return !wVar.a();
    }

    @Override // com.facebook.imagepipeline.memory.a
    protected int m(int i3) {
        if (i3 <= 0) {
            throw new a.b(Integer.valueOf(i3));
        }
        for (int i4 : this.f6065k) {
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
    public void j(w wVar) {
        k.g(wVar);
        wVar.close();
    }
}
