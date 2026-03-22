package kotlin.reflect.jvm.internal.impl.builtins;

import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.FunctionReference;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Reflection;
import kotlin.reflect.KDeclarationContainer;
import kotlin.reflect.jvm.internal.impl.name.FqName;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public /* synthetic */ class CompanionObjectMapping$classIds$1 extends FunctionReference implements Function1<PrimitiveType, FqName> {
    public CompanionObjectMapping$classIds$1(StandardNames standardNames) {
        super(1, standardNames);
    }

    @Override // kotlin.jvm.internal.CallableReference, kotlin.reflect.KCallable
    @NotNull
    public final String getName() {
        return "getPrimitiveFqName";
    }

    @Override // kotlin.jvm.internal.CallableReference
    @NotNull
    public final KDeclarationContainer getOwner() {
        return Reflection.getOrCreateKotlinClass(StandardNames.class);
    }

    @Override // kotlin.jvm.internal.CallableReference
    @NotNull
    public final String getSignature() {
        return "getPrimitiveFqName(Lorg/jetbrains/kotlin/builtins/PrimitiveType;)Lorg/jetbrains/kotlin/name/FqName;";
    }

    @Override // kotlin.jvm.functions.Function1
    @NotNull
    public final FqName invoke(@NotNull PrimitiveType p0) {
        Intrinsics.checkNotNullParameter(p0, "p0");
        return StandardNames.getPrimitiveFqName(p0);
    }
}
