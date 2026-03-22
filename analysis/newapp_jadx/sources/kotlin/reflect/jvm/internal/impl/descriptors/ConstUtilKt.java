package kotlin.reflect.jvm.internal.impl.descriptors;

/* loaded from: classes.dex */
public final class ConstUtilKt {
    /* JADX WARN: Code restructure failed: missing block: B:11:0x0017, code lost:
    
        if (kotlin.reflect.jvm.internal.impl.types.TypeUtils.isNullableType(r1) != false) goto L8;
     */
    /* JADX WARN: Code restructure failed: missing block: B:4:0x0011, code lost:
    
        if (kotlin.reflect.jvm.internal.impl.builtins.UnsignedTypes.isUnsignedType(r1) != false) goto L6;
     */
    /* JADX WARN: Code restructure failed: missing block: B:6:0x001d, code lost:
    
        if (kotlin.reflect.jvm.internal.impl.builtins.KotlinBuiltIns.isString(r1) == false) goto L11;
     */
    /* JADX WARN: Code restructure failed: missing block: B:7:0x0020, code lost:
    
        return false;
     */
    /* JADX WARN: Code restructure failed: missing block: B:9:0x0022, code lost:
    
        return true;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final boolean canBeUsedForConstVal(@org.jetbrains.annotations.NotNull kotlin.reflect.jvm.internal.impl.types.KotlinType r1) {
        /*
            java.lang.String r0 = "<this>"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r1, r0)
            boolean r0 = kotlin.reflect.jvm.internal.impl.builtins.KotlinBuiltIns.isPrimitiveType(r1)
            if (r0 != 0) goto L13
            kotlin.reflect.jvm.internal.impl.builtins.UnsignedTypes r0 = kotlin.reflect.jvm.internal.impl.builtins.UnsignedTypes.INSTANCE
            boolean r0 = kotlin.reflect.jvm.internal.impl.builtins.UnsignedTypes.isUnsignedType(r1)
            if (r0 == 0) goto L19
        L13:
            boolean r0 = kotlin.reflect.jvm.internal.impl.types.TypeUtils.isNullableType(r1)
            if (r0 == 0) goto L22
        L19:
            boolean r1 = kotlin.reflect.jvm.internal.impl.builtins.KotlinBuiltIns.isString(r1)
            if (r1 == 0) goto L20
            goto L22
        L20:
            r1 = 0
            goto L23
        L22:
            r1 = 1
        L23:
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: kotlin.reflect.jvm.internal.impl.descriptors.ConstUtilKt.canBeUsedForConstVal(kotlin.reflect.jvm.internal.impl.types.KotlinType):boolean");
    }
}
