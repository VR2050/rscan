package kotlin.reflect.jvm.internal.impl.builtins;

import androidx.exifinterface.media.ExifInterface;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import kotlin.collections.CollectionsKt__CollectionsJVMKt;
import kotlin.collections.CollectionsKt__IterablesKt;
import kotlin.collections.CollectionsKt___CollectionsKt;
import kotlin.jvm.internal.Intrinsics;
import kotlin.reflect.jvm.internal.impl.descriptors.ClassKind;
import kotlin.reflect.jvm.internal.impl.descriptors.DescriptorVisibilities;
import kotlin.reflect.jvm.internal.impl.descriptors.DescriptorVisibility;
import kotlin.reflect.jvm.internal.impl.descriptors.Modality;
import kotlin.reflect.jvm.internal.impl.descriptors.ModuleDescriptor;
import kotlin.reflect.jvm.internal.impl.descriptors.SourceElement;
import kotlin.reflect.jvm.internal.impl.descriptors.annotations.Annotations;
import kotlin.reflect.jvm.internal.impl.descriptors.impl.EmptyPackageFragmentDescriptor;
import kotlin.reflect.jvm.internal.impl.descriptors.impl.MutableClassDescriptor;
import kotlin.reflect.jvm.internal.impl.descriptors.impl.TypeParameterDescriptorImpl;
import kotlin.reflect.jvm.internal.impl.name.FqName;
import kotlin.reflect.jvm.internal.impl.name.Name;
import kotlin.reflect.jvm.internal.impl.storage.LockBasedStorageManager;
import kotlin.reflect.jvm.internal.impl.storage.StorageManager;
import kotlin.reflect.jvm.internal.impl.types.ErrorUtils;
import kotlin.reflect.jvm.internal.impl.types.KotlinType;
import kotlin.reflect.jvm.internal.impl.types.KotlinTypeFactory;
import kotlin.reflect.jvm.internal.impl.types.SimpleType;
import kotlin.reflect.jvm.internal.impl.types.TypeConstructor;
import kotlin.reflect.jvm.internal.impl.types.TypeProjection;
import kotlin.reflect.jvm.internal.impl.types.Variance;
import kotlin.reflect.jvm.internal.impl.types.typeUtil.TypeUtilsKt;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

/* loaded from: classes.dex */
public final class SuspendFunctionTypesKt {

    @NotNull
    private static final MutableClassDescriptor FAKE_CONTINUATION_CLASS_DESCRIPTOR_EXPERIMENTAL;

    @NotNull
    private static final MutableClassDescriptor FAKE_CONTINUATION_CLASS_DESCRIPTOR_RELEASE;

    static {
        ModuleDescriptor errorModule = ErrorUtils.getErrorModule();
        Intrinsics.checkNotNullExpressionValue(errorModule, "getErrorModule()");
        EmptyPackageFragmentDescriptor emptyPackageFragmentDescriptor = new EmptyPackageFragmentDescriptor(errorModule, StandardNames.COROUTINES_PACKAGE_FQ_NAME_EXPERIMENTAL);
        ClassKind classKind = ClassKind.INTERFACE;
        Name shortName = StandardNames.CONTINUATION_INTERFACE_FQ_NAME_EXPERIMENTAL.shortName();
        SourceElement sourceElement = SourceElement.NO_SOURCE;
        StorageManager storageManager = LockBasedStorageManager.NO_LOCKS;
        MutableClassDescriptor mutableClassDescriptor = new MutableClassDescriptor(emptyPackageFragmentDescriptor, classKind, false, false, shortName, sourceElement, storageManager);
        Modality modality = Modality.ABSTRACT;
        mutableClassDescriptor.setModality(modality);
        DescriptorVisibility descriptorVisibility = DescriptorVisibilities.PUBLIC;
        mutableClassDescriptor.setVisibility(descriptorVisibility);
        Annotations.Companion companion = Annotations.Companion;
        Annotations empty = companion.getEMPTY();
        Variance variance = Variance.IN_VARIANCE;
        mutableClassDescriptor.setTypeParameterDescriptors(CollectionsKt__CollectionsJVMKt.listOf(TypeParameterDescriptorImpl.createWithDefaultBound(mutableClassDescriptor, empty, false, variance, Name.identifier(ExifInterface.GPS_DIRECTION_TRUE), 0, storageManager)));
        mutableClassDescriptor.createTypeConstructor();
        FAKE_CONTINUATION_CLASS_DESCRIPTOR_EXPERIMENTAL = mutableClassDescriptor;
        ModuleDescriptor errorModule2 = ErrorUtils.getErrorModule();
        Intrinsics.checkNotNullExpressionValue(errorModule2, "getErrorModule()");
        MutableClassDescriptor mutableClassDescriptor2 = new MutableClassDescriptor(new EmptyPackageFragmentDescriptor(errorModule2, StandardNames.COROUTINES_PACKAGE_FQ_NAME_RELEASE), classKind, false, false, StandardNames.CONTINUATION_INTERFACE_FQ_NAME_RELEASE.shortName(), sourceElement, storageManager);
        mutableClassDescriptor2.setModality(modality);
        mutableClassDescriptor2.setVisibility(descriptorVisibility);
        mutableClassDescriptor2.setTypeParameterDescriptors(CollectionsKt__CollectionsJVMKt.listOf(TypeParameterDescriptorImpl.createWithDefaultBound(mutableClassDescriptor2, companion.getEMPTY(), false, variance, Name.identifier(ExifInterface.GPS_DIRECTION_TRUE), 0, storageManager)));
        mutableClassDescriptor2.createTypeConstructor();
        FAKE_CONTINUATION_CLASS_DESCRIPTOR_RELEASE = mutableClassDescriptor2;
    }

    public static final boolean isContinuation(@Nullable FqName fqName, boolean z) {
        return z ? Intrinsics.areEqual(fqName, StandardNames.CONTINUATION_INTERFACE_FQ_NAME_RELEASE) : Intrinsics.areEqual(fqName, StandardNames.CONTINUATION_INTERFACE_FQ_NAME_EXPERIMENTAL);
    }

    @NotNull
    public static final SimpleType transformSuspendFunctionToRuntimeFunctionType(@NotNull KotlinType suspendFunType, boolean z) {
        SimpleType createFunctionType;
        Intrinsics.checkNotNullParameter(suspendFunType, "suspendFunType");
        FunctionTypesKt.isSuspendFunctionType(suspendFunType);
        KotlinBuiltIns builtIns = TypeUtilsKt.getBuiltIns(suspendFunType);
        Annotations annotations = suspendFunType.getAnnotations();
        KotlinType receiverTypeFromFunctionType = FunctionTypesKt.getReceiverTypeFromFunctionType(suspendFunType);
        List<TypeProjection> valueParameterTypesFromFunctionType = FunctionTypesKt.getValueParameterTypesFromFunctionType(suspendFunType);
        ArrayList arrayList = new ArrayList(CollectionsKt__IterablesKt.collectionSizeOrDefault(valueParameterTypesFromFunctionType, 10));
        Iterator<T> it = valueParameterTypesFromFunctionType.iterator();
        while (it.hasNext()) {
            arrayList.add(((TypeProjection) it.next()).getType());
        }
        KotlinTypeFactory kotlinTypeFactory = KotlinTypeFactory.INSTANCE;
        Annotations empty = Annotations.Companion.getEMPTY();
        TypeConstructor typeConstructor = z ? FAKE_CONTINUATION_CLASS_DESCRIPTOR_RELEASE.getTypeConstructor() : FAKE_CONTINUATION_CLASS_DESCRIPTOR_EXPERIMENTAL.getTypeConstructor();
        Intrinsics.checkNotNullExpressionValue(typeConstructor, "if (isReleaseCoroutines) FAKE_CONTINUATION_CLASS_DESCRIPTOR_RELEASE.typeConstructor\n                    else FAKE_CONTINUATION_CLASS_DESCRIPTOR_EXPERIMENTAL.typeConstructor");
        List plus = CollectionsKt___CollectionsKt.plus((Collection<? extends SimpleType>) arrayList, KotlinTypeFactory.simpleType$default(empty, typeConstructor, CollectionsKt__CollectionsJVMKt.listOf(TypeUtilsKt.asTypeProjection(FunctionTypesKt.getReturnTypeFromFunctionType(suspendFunType))), false, null, 16, null));
        SimpleType nullableAnyType = TypeUtilsKt.getBuiltIns(suspendFunType).getNullableAnyType();
        Intrinsics.checkNotNullExpressionValue(nullableAnyType, "suspendFunType.builtIns.nullableAnyType");
        createFunctionType = FunctionTypesKt.createFunctionType(builtIns, annotations, receiverTypeFromFunctionType, plus, null, nullableAnyType, (r14 & 64) != 0 ? false : false);
        return createFunctionType.makeNullableAsSpecified(suspendFunType.isMarkedNullable());
    }
}
