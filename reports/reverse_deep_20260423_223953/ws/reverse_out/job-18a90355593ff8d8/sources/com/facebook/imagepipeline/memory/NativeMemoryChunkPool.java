package com.facebook.imagepipeline.memory;

import Q0.F;
import Q0.G;
import a0.InterfaceC0218d;

/* JADX INFO: loaded from: classes.dex */
public class NativeMemoryChunkPool extends e {
    public NativeMemoryChunkPool(InterfaceC0218d interfaceC0218d, F f3, G g3) {
        super(interfaceC0218d, f3, g3);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.facebook.imagepipeline.memory.a
    /* JADX INFO: renamed from: D, reason: merged with bridge method [inline-methods] */
    public NativeMemoryChunk f(int i3) {
        return new NativeMemoryChunk(i3);
    }
}
