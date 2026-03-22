package kotlin.reflect.jvm.internal.impl.types.checker;

import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.reflect.jvm.internal.impl.types.AbstractTypeCheckerContext;
import kotlin.reflect.jvm.internal.impl.types.KotlinType;
import kotlin.reflect.jvm.internal.impl.types.SimpleType;
import kotlin.reflect.jvm.internal.impl.types.TypeConstructorSubstitution;
import kotlin.reflect.jvm.internal.impl.types.TypeSubstitutor;
import kotlin.reflect.jvm.internal.impl.types.UnwrappedType;
import kotlin.reflect.jvm.internal.impl.types.Variance;
import kotlin.reflect.jvm.internal.impl.types.checker.KotlinTypePreparator;
import kotlin.reflect.jvm.internal.impl.types.checker.KotlinTypeRefiner;
import kotlin.reflect.jvm.internal.impl.types.model.KotlinTypeMarker;
import kotlin.reflect.jvm.internal.impl.types.model.SimpleTypeMarker;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public class ClassicTypeCheckerContext extends AbstractTypeCheckerContext {

    @NotNull
    public static final Companion Companion = new Companion(null);
    private final boolean allowedTypeVariable;
    private final boolean errorTypeEqualsToAnything;

    @NotNull
    private final KotlinTypePreparator kotlinTypePreparator;

    @NotNull
    private final KotlinTypeRefiner kotlinTypeRefiner;
    private final boolean stubTypeEqualsToAnything;

    @NotNull
    private final ClassicTypeSystemContext typeSystemContext;

    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        /* JADX WARN: Multi-variable type inference failed */
        @NotNull
        public final AbstractTypeCheckerContext.SupertypesPolicy.DoCustomTransform classicSubstitutionSupertypePolicy(@NotNull final ClassicTypeSystemContext classicTypeSystemContext, @NotNull SimpleTypeMarker type) {
            String errorMessage;
            Intrinsics.checkNotNullParameter(classicTypeSystemContext, "<this>");
            Intrinsics.checkNotNullParameter(type, "type");
            if (type instanceof SimpleType) {
                final TypeSubstitutor buildSubstitutor = TypeConstructorSubstitution.Companion.create((KotlinType) type).buildSubstitutor();
                return new AbstractTypeCheckerContext.SupertypesPolicy.DoCustomTransform() { // from class: kotlin.reflect.jvm.internal.impl.types.checker.ClassicTypeCheckerContext$Companion$classicSubstitutionSupertypePolicy$2
                    @Override // kotlin.reflect.jvm.internal.impl.types.AbstractTypeCheckerContext.SupertypesPolicy
                    @NotNull
                    /* renamed from: transformType */
                    public SimpleTypeMarker mo7315transformType(@NotNull AbstractTypeCheckerContext context, @NotNull KotlinTypeMarker type2) {
                        Intrinsics.checkNotNullParameter(context, "context");
                        Intrinsics.checkNotNullParameter(type2, "type");
                        ClassicTypeSystemContext classicTypeSystemContext2 = ClassicTypeSystemContext.this;
                        KotlinType safeSubstitute = buildSubstitutor.safeSubstitute((KotlinType) classicTypeSystemContext2.lowerBoundIfFlexible(type2), Variance.INVARIANT);
                        Intrinsics.checkNotNullExpressionValue(safeSubstitute, "substitutor.safeSubstitute(\n                        type.lowerBoundIfFlexible() as KotlinType,\n                        Variance.INVARIANT\n                    )");
                        SimpleTypeMarker asSimpleType = classicTypeSystemContext2.asSimpleType(safeSubstitute);
                        Intrinsics.checkNotNull(asSimpleType);
                        return asSimpleType;
                    }
                };
            }
            errorMessage = ClassicTypeCheckerContextKt.errorMessage(type);
            throw new IllegalArgumentException(errorMessage.toString());
        }
    }

    public /* synthetic */ ClassicTypeCheckerContext(boolean z, boolean z2, boolean z3, KotlinTypeRefiner kotlinTypeRefiner, KotlinTypePreparator kotlinTypePreparator, ClassicTypeSystemContext classicTypeSystemContext, int i2, DefaultConstructorMarker defaultConstructorMarker) {
        this(z, (i2 & 2) != 0 ? true : z2, (i2 & 4) == 0 ? z3 : true, (i2 & 8) != 0 ? KotlinTypeRefiner.Default.INSTANCE : kotlinTypeRefiner, (i2 & 16) != 0 ? KotlinTypePreparator.Default.INSTANCE : kotlinTypePreparator, (i2 & 32) != 0 ? SimpleClassicTypeSystemContext.INSTANCE : classicTypeSystemContext);
    }

    @Override // kotlin.reflect.jvm.internal.impl.types.AbstractTypeCheckerContext
    public boolean isAllowedTypeVariable(@NotNull KotlinTypeMarker kotlinTypeMarker) {
        Intrinsics.checkNotNullParameter(kotlinTypeMarker, "<this>");
        return (kotlinTypeMarker instanceof UnwrappedType) && this.allowedTypeVariable && (((UnwrappedType) kotlinTypeMarker).getConstructor() instanceof NewTypeVariableConstructor);
    }

    @Override // kotlin.reflect.jvm.internal.impl.types.AbstractTypeCheckerContext
    public boolean isErrorTypeEqualsToAnything() {
        return this.errorTypeEqualsToAnything;
    }

    @Override // kotlin.reflect.jvm.internal.impl.types.AbstractTypeCheckerContext
    public boolean isStubTypeEqualsToAnything() {
        return this.stubTypeEqualsToAnything;
    }

    @Override // kotlin.reflect.jvm.internal.impl.types.AbstractTypeCheckerContext
    @NotNull
    public KotlinTypeMarker prepareType(@NotNull KotlinTypeMarker type) {
        String errorMessage;
        Intrinsics.checkNotNullParameter(type, "type");
        if (type instanceof KotlinType) {
            return this.kotlinTypePreparator.prepareType(((KotlinType) type).unwrap());
        }
        errorMessage = ClassicTypeCheckerContextKt.errorMessage(type);
        throw new IllegalArgumentException(errorMessage.toString());
    }

    @Override // kotlin.reflect.jvm.internal.impl.types.AbstractTypeCheckerContext
    @NotNull
    public KotlinTypeMarker refineType(@NotNull KotlinTypeMarker type) {
        String errorMessage;
        Intrinsics.checkNotNullParameter(type, "type");
        if (type instanceof KotlinType) {
            return this.kotlinTypeRefiner.refineType((KotlinType) type);
        }
        errorMessage = ClassicTypeCheckerContextKt.errorMessage(type);
        throw new IllegalArgumentException(errorMessage.toString());
    }

    @Override // kotlin.reflect.jvm.internal.impl.types.AbstractTypeCheckerContext
    @NotNull
    public ClassicTypeSystemContext getTypeSystemContext() {
        return this.typeSystemContext;
    }

    @Override // kotlin.reflect.jvm.internal.impl.types.AbstractTypeCheckerContext
    @NotNull
    public AbstractTypeCheckerContext.SupertypesPolicy.DoCustomTransform substitutionSupertypePolicy(@NotNull SimpleTypeMarker type) {
        Intrinsics.checkNotNullParameter(type, "type");
        return Companion.classicSubstitutionSupertypePolicy(getTypeSystemContext(), type);
    }

    public ClassicTypeCheckerContext(boolean z, boolean z2, boolean z3, @NotNull KotlinTypeRefiner kotlinTypeRefiner, @NotNull KotlinTypePreparator kotlinTypePreparator, @NotNull ClassicTypeSystemContext typeSystemContext) {
        Intrinsics.checkNotNullParameter(kotlinTypeRefiner, "kotlinTypeRefiner");
        Intrinsics.checkNotNullParameter(kotlinTypePreparator, "kotlinTypePreparator");
        Intrinsics.checkNotNullParameter(typeSystemContext, "typeSystemContext");
        this.errorTypeEqualsToAnything = z;
        this.stubTypeEqualsToAnything = z2;
        this.allowedTypeVariable = z3;
        this.kotlinTypeRefiner = kotlinTypeRefiner;
        this.kotlinTypePreparator = kotlinTypePreparator;
        this.typeSystemContext = typeSystemContext;
    }
}
