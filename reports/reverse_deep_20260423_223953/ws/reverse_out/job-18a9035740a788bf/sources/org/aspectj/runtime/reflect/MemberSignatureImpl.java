package org.aspectj.runtime.reflect;

import org.aspectj.lang.reflect.MemberSignature;

/* JADX INFO: loaded from: classes3.dex */
abstract class MemberSignatureImpl extends SignatureImpl implements MemberSignature {
    MemberSignatureImpl(int modifiers, String name, Class declaringType) {
        super(modifiers, name, declaringType);
    }

    public MemberSignatureImpl(String stringRep) {
        super(stringRep);
    }
}
