package kotlin.reflect.jvm.internal.impl.serialization.deserialization;

import kotlin.jvm.internal.Intrinsics;
import kotlin.reflect.jvm.internal.impl.descriptors.CallableMemberDescriptor;
import kotlin.reflect.jvm.internal.impl.descriptors.DescriptorVisibilities;
import kotlin.reflect.jvm.internal.impl.descriptors.DescriptorVisibility;
import kotlin.reflect.jvm.internal.impl.metadata.ProtoBuf;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

/* loaded from: classes.dex */
public final class ProtoEnumFlagsUtilsKt {

    public /* synthetic */ class WhenMappings {
        public static final /* synthetic */ int[] $EnumSwitchMapping$0;
        public static final /* synthetic */ int[] $EnumSwitchMapping$1;
        public static final /* synthetic */ int[] $EnumSwitchMapping$2;

        static {
            ProtoBuf.MemberKind.values();
            int[] iArr = new int[4];
            iArr[ProtoBuf.MemberKind.DECLARATION.ordinal()] = 1;
            iArr[ProtoBuf.MemberKind.FAKE_OVERRIDE.ordinal()] = 2;
            iArr[ProtoBuf.MemberKind.DELEGATION.ordinal()] = 3;
            iArr[ProtoBuf.MemberKind.SYNTHESIZED.ordinal()] = 4;
            $EnumSwitchMapping$0 = iArr;
            CallableMemberDescriptor.Kind.values();
            int[] iArr2 = new int[4];
            iArr2[CallableMemberDescriptor.Kind.DECLARATION.ordinal()] = 1;
            iArr2[CallableMemberDescriptor.Kind.FAKE_OVERRIDE.ordinal()] = 2;
            iArr2[CallableMemberDescriptor.Kind.DELEGATION.ordinal()] = 3;
            iArr2[CallableMemberDescriptor.Kind.SYNTHESIZED.ordinal()] = 4;
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
        }
    }

    @NotNull
    public static final DescriptorVisibility descriptorVisibility(@NotNull ProtoEnumFlags protoEnumFlags, @Nullable ProtoBuf.Visibility visibility) {
        Intrinsics.checkNotNullParameter(protoEnumFlags, "<this>");
        switch (visibility == null ? -1 : WhenMappings.$EnumSwitchMapping$2[visibility.ordinal()]) {
            case 1:
                DescriptorVisibility INTERNAL = DescriptorVisibilities.INTERNAL;
                Intrinsics.checkNotNullExpressionValue(INTERNAL, "INTERNAL");
                return INTERNAL;
            case 2:
                DescriptorVisibility PRIVATE = DescriptorVisibilities.PRIVATE;
                Intrinsics.checkNotNullExpressionValue(PRIVATE, "PRIVATE");
                return PRIVATE;
            case 3:
                DescriptorVisibility PRIVATE_TO_THIS = DescriptorVisibilities.PRIVATE_TO_THIS;
                Intrinsics.checkNotNullExpressionValue(PRIVATE_TO_THIS, "PRIVATE_TO_THIS");
                return PRIVATE_TO_THIS;
            case 4:
                DescriptorVisibility PROTECTED = DescriptorVisibilities.PROTECTED;
                Intrinsics.checkNotNullExpressionValue(PROTECTED, "PROTECTED");
                return PROTECTED;
            case 5:
                DescriptorVisibility PUBLIC = DescriptorVisibilities.PUBLIC;
                Intrinsics.checkNotNullExpressionValue(PUBLIC, "PUBLIC");
                return PUBLIC;
            case 6:
                DescriptorVisibility LOCAL = DescriptorVisibilities.LOCAL;
                Intrinsics.checkNotNullExpressionValue(LOCAL, "LOCAL");
                return LOCAL;
            default:
                DescriptorVisibility PRIVATE2 = DescriptorVisibilities.PRIVATE;
                Intrinsics.checkNotNullExpressionValue(PRIVATE2, "PRIVATE");
                return PRIVATE2;
        }
    }

    @NotNull
    public static final CallableMemberDescriptor.Kind memberKind(@NotNull ProtoEnumFlags protoEnumFlags, @Nullable ProtoBuf.MemberKind memberKind) {
        Intrinsics.checkNotNullParameter(protoEnumFlags, "<this>");
        int i2 = memberKind == null ? -1 : WhenMappings.$EnumSwitchMapping$0[memberKind.ordinal()];
        return i2 != 1 ? i2 != 2 ? i2 != 3 ? i2 != 4 ? CallableMemberDescriptor.Kind.DECLARATION : CallableMemberDescriptor.Kind.SYNTHESIZED : CallableMemberDescriptor.Kind.DELEGATION : CallableMemberDescriptor.Kind.FAKE_OVERRIDE : CallableMemberDescriptor.Kind.DECLARATION;
    }
}
