package com.google.firebase.abt.component;

import com.google.firebase.components.ComponentContainer;
import com.google.firebase.components.ComponentFactory;

/* JADX INFO: compiled from: com.google.firebase:firebase-abt@@19.0.0 */
/* JADX INFO: loaded from: classes.dex */
final /* synthetic */ class AbtRegistrar$$Lambda$1 implements ComponentFactory {
    private static final AbtRegistrar$$Lambda$1 instance = new AbtRegistrar$$Lambda$1();

    private AbtRegistrar$$Lambda$1() {
    }

    @Override // com.google.firebase.components.ComponentFactory
    public Object create(ComponentContainer componentContainer) {
        return AbtRegistrar.lambda$getComponents$0(componentContainer);
    }
}
