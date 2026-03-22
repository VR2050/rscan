package kotlin.reflect.jvm.internal.impl.serialization.deserialization;

import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;
import kotlin.reflect.jvm.internal.impl.descriptors.ClassKind;
import kotlin.reflect.jvm.internal.impl.descriptors.Modality;
import kotlin.reflect.jvm.internal.impl.metadata.ProtoBuf;
import kotlin.reflect.jvm.internal.impl.types.Variance;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

/* loaded from: classes.dex */
public final class ProtoEnumFlags {

    @NotNull
    public static final ProtoEnumFlags INSTANCE = new ProtoEnumFlags();

    public /* synthetic */ class WhenMappings {
        public static final /* synthetic */ int[] $EnumSwitchMapping$0;
        public static final /* synthetic */ int[] $EnumSwitchMapping$1;
        public static final /* synthetic */ int[] $EnumSwitchMapping$2;
        public static final /* synthetic */ int[] $EnumSwitchMapping$3;
        public static final /* synthetic */ int[] $EnumSwitchMapping$4;
        public static final /* synthetic */ int[] $EnumSwitchMapping$5;
        public static final /* synthetic */ int[] $EnumSwitchMapping$6;
        public static final /* synthetic */ int[] $EnumSwitchMapping$7;

        static {
            ProtoBuf.Modality.values();
            int[] iArr = new int[4];
            iArr[ProtoBuf.Modality.FINAL.ordinal()] = 1;
            iArr[ProtoBuf.Modality.OPEN.ordinal()] = 2;
            iArr[ProtoBuf.Modality.ABSTRACT.ordinal()] = 3;
            iArr[ProtoBuf.Modality.SEALED.ordinal()] = 4;
            $EnumSwitchMapping$0 = iArr;
            Modality.values();
            int[] iArr2 = new int[4];
            iArr2[Modality.FINAL.ordinal()] = 1;
            iArr2[Modality.OPEN.ordinal()] = 2;
            iArr2[Modality.ABSTRACT.ordinal()] = 3;
            iArr2[Modality.SEALED.ordinal()] = 4;
            $EnumSwitchMapping$1 = iArr2;
            ProtoBuf.Visibility.values();
            int[] iArr3 = new int[6];
            iArr3[ProtoBuf.Visibility.INTERNAL.ordinal()] = 1;
            iArr3[ProtoBuf.Visibility.PRIVATE.ordinal()] = 2;
            iArr3[ProtoBuf.Visibility.PRIVATE_TO_THIS.ordinal()] = 3;
            iArr3[ProtoBuf.Visibility.PROTECTED.ordinal()] = 4;
            iArr3[ProtoBuf.Visibility.PUBLIC.ordinal()] = 5;
            iArr3[ProtoBuf.Visibility.LOCAL.ordinal()] = 6;
            $EnumSwitchMapping$2 = iArr3;
            ProtoBuf.Class.Kind.values();
            int[] iArr4 = new int[7];
            iArr4[ProtoBuf.Class.Kind.CLASS.ordinal()] = 1;
            iArr4[ProtoBuf.Class.Kind.INTERFACE.ordinal()] = 2;
            iArr4[ProtoBuf.Class.Kind.ENUM_CLASS.ordinal()] = 3;
            iArr4[ProtoBuf.Class.Kind.ENUM_ENTRY.ordinal()] = 4;
            iArr4[ProtoBuf.Class.Kind.ANNOTATION_CLASS.ordinal()] = 5;
            iArr4[ProtoBuf.Class.Kind.OBJECT.ordinal()] = 6;
            iArr4[ProtoBuf.Class.Kind.COMPANION_OBJECT.ordinal()] = 7;
            $EnumSwitchMapping$3 = iArr4;
            ClassKind.values();
            int[] iArr5 = new int[6];
            iArr5[ClassKind.CLASS.ordinal()] = 1;
            iArr5[ClassKind.INTERFACE.ordinal()] = 2;
            iArr5[ClassKind.ENUM_CLASS.ordinal()] = 3;
            iArr5[ClassKind.ENUM_ENTRY.ordinal()] = 4;
            iArr5[ClassKind.ANNOTATION_CLASS.ordinal()] = 5;
            iArr5[ClassKind.OBJECT.ordinal()] = 6;
            $EnumSwitchMapping$4 = iArr5;
            ProtoBuf.TypeParameter.Variance.values();
            int[] iArr6 = new int[3];
            iArr6[ProtoBuf.TypeParameter.Variance.IN.ordinal()] = 1;
            iArr6[ProtoBuf.TypeParameter.Variance.OUT.ordinal()] = 2;
            iArr6[ProtoBuf.TypeParameter.Variance.INV.ordinal()] = 3;
            $EnumSwitchMapping$5 = iArr6;
            ProtoBuf.Type.Argument.Projection.values();
            int[] iArr7 = new int[4];
            iArr7[ProtoBuf.Type.Argument.Projection.IN.ordinal()] = 1;
            iArr7[ProtoBuf.Type.Argument.Projection.OUT.ordinal()] = 2;
            iArr7[ProtoBuf.Type.Argument.Projection.INV.ordinal()] = 3;
            iArr7[ProtoBuf.Type.Argument.Projection.STAR.ordinal()] = 4;
            $EnumSwitchMapping$6 = iArr7;
            Variance.values();
            int[] iArr8 = new int[3];
            iArr8[Variance.IN_VARIANCE.ordinal()] = 1;
            iArr8[Variance.OUT_VARIANCE.ordinal()] = 2;
            iArr8[Variance.INVARIANT.ordinal()] = 3;
            $EnumSwitchMapping$7 = iArr8;
        }
    }

    private ProtoEnumFlags() {
    }

    @NotNull
    public final ClassKind classKind(@Nullable ProtoBuf.Class.Kind kind) {
        switch (kind == null ? -1 : WhenMappings.$EnumSwitchMapping$3[kind.ordinal()]) {
        }
        return ClassKind.CLASS;
    }

    @NotNull
    public final Modality modality(@Nullable ProtoBuf.Modality modality) {
        int i2 = modality == null ? -1 : WhenMappings.$EnumSwitchMapping$0[modality.ordinal()];
        return i2 != 1 ? i2 != 2 ? i2 != 3 ? i2 != 4 ? Modality.FINAL : Modality.SEALED : Modality.ABSTRACT : Modality.OPEN : Modality.FINAL;
    }

    @NotNull
    public final Variance variance(@NotNull ProtoBuf.TypeParameter.Variance variance) {
        Intrinsics.checkNotNullParameter(variance, "variance");
        int ordinal = variance.ordinal();
        if (ordinal == 0) {
            return Variance.IN_VARIANCE;
        }
        if (ordinal == 1) {
            return Variance.OUT_VARIANCE;
        }
        if (ordinal == 2) {
            return Variance.INVARIANT;
        }
        throw new NoWhenBranchMatchedException();
    }

    @NotNull
    public final Variance variance(@NotNull ProtoBuf.Type.Argument.Projection projection) {
        Intrinsics.checkNotNullParameter(projection, "projection");
        int ordinal = projection.ordinal();
        if (ordinal == 0) {
            return Variance.IN_VARIANCE;
        }
        if (ordinal == 1) {
            return Variance.OUT_VARIANCE;
        }
        if (ordinal == 2) {
            return Variance.INVARIANT;
        }
        if (ordinal != 3) {
            throw new NoWhenBranchMatchedException();
        }
        throw new IllegalArgumentException(Intrinsics.stringPlus("Only IN, OUT and INV are supported. Actual argument: ", projection));
    }
}
