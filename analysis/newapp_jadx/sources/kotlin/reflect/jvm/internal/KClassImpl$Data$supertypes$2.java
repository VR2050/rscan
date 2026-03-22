package kotlin.reflect.jvm.internal;

import androidx.exifinterface.media.ExifInterface;
import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import kotlin.Metadata;
import kotlin.collections.ArraysKt___ArraysKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Lambda;
import kotlin.reflect.jvm.internal.KClassImpl;
import kotlin.reflect.jvm.internal.impl.builtins.KotlinBuiltIns;
import kotlin.reflect.jvm.internal.impl.descriptors.ClassDescriptor;
import kotlin.reflect.jvm.internal.impl.descriptors.ClassKind;
import kotlin.reflect.jvm.internal.impl.descriptors.ClassifierDescriptor;
import kotlin.reflect.jvm.internal.impl.resolve.DescriptorUtils;
import kotlin.reflect.jvm.internal.impl.resolve.descriptorUtil.DescriptorUtilsKt;
import kotlin.reflect.jvm.internal.impl.types.KotlinType;
import kotlin.reflect.jvm.internal.impl.types.SimpleType;
import kotlin.reflect.jvm.internal.impl.types.TypeConstructor;
import kotlin.reflect.jvm.internal.impl.utils.CollectionsKt;
import org.jetbrains.annotations.NotNull;
import p005b.p131d.p132a.p133a.C1499a;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0012\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010 \n\u0002\u0018\u0002\n\u0002\b\u0004\u0010\u0007\u001a\u0016\u0012\u0004\u0012\u00020\u0003 \u0004*\n\u0012\u0004\u0012\u00020\u0003\u0018\u00010\u00020\u0002\"\b\b\u0000\u0010\u0001*\u00020\u0000H\n¢\u0006\u0004\b\u0005\u0010\u0006"}, m5311d2 = {"", ExifInterface.GPS_DIRECTION_TRUE, "", "Lkotlin/reflect/jvm/internal/KTypeImpl;", "kotlin.jvm.PlatformType", "invoke", "()Ljava/util/List;", "<anonymous>"}, m5312k = 3, m5313mv = {1, 5, 1})
/* loaded from: classes.dex */
public final class KClassImpl$Data$supertypes$2 extends Lambda implements Function0<List<? extends KTypeImpl>> {
    public final /* synthetic */ KClassImpl.Data this$0;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public KClassImpl$Data$supertypes$2(KClassImpl.Data data) {
        super(0);
        this.this$0 = data;
    }

    @Override // kotlin.jvm.functions.Function0
    public final List<? extends KTypeImpl> invoke() {
        TypeConstructor typeConstructor = this.this$0.getDescriptor().getTypeConstructor();
        Intrinsics.checkNotNullExpressionValue(typeConstructor, "descriptor.typeConstructor");
        Collection<KotlinType> mo7312getSupertypes = typeConstructor.mo7312getSupertypes();
        Intrinsics.checkNotNullExpressionValue(mo7312getSupertypes, "descriptor.typeConstructor.supertypes");
        ArrayList arrayList = new ArrayList(mo7312getSupertypes.size());
        for (final KotlinType kotlinType : mo7312getSupertypes) {
            Intrinsics.checkNotNullExpressionValue(kotlinType, "kotlinType");
            arrayList.add(new KTypeImpl(kotlinType, new Function0<Type>() { // from class: kotlin.reflect.jvm.internal.KClassImpl$Data$supertypes$2$$special$$inlined$mapTo$lambda$1
                /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                {
                    super(0);
                }

                @Override // kotlin.jvm.functions.Function0
                @NotNull
                public final Type invoke() {
                    ClassifierDescriptor mo7311getDeclarationDescriptor = KotlinType.this.getConstructor().mo7311getDeclarationDescriptor();
                    if (!(mo7311getDeclarationDescriptor instanceof ClassDescriptor)) {
                        throw new KotlinReflectionInternalError("Supertype not a class: " + mo7311getDeclarationDescriptor);
                    }
                    Class<?> javaClass = UtilKt.toJavaClass((ClassDescriptor) mo7311getDeclarationDescriptor);
                    if (javaClass == null) {
                        StringBuilder m586H = C1499a.m586H("Unsupported superclass of ");
                        m586H.append(this.this$0);
                        m586H.append(": ");
                        m586H.append(mo7311getDeclarationDescriptor);
                        throw new KotlinReflectionInternalError(m586H.toString());
                    }
                    if (Intrinsics.areEqual(KClassImpl.this.getJClass().getSuperclass(), javaClass)) {
                        Type genericSuperclass = KClassImpl.this.getJClass().getGenericSuperclass();
                        Intrinsics.checkNotNullExpressionValue(genericSuperclass, "jClass.genericSuperclass");
                        return genericSuperclass;
                    }
                    Class<?>[] interfaces = KClassImpl.this.getJClass().getInterfaces();
                    Intrinsics.checkNotNullExpressionValue(interfaces, "jClass.interfaces");
                    int indexOf = ArraysKt___ArraysKt.indexOf(interfaces, javaClass);
                    if (indexOf >= 0) {
                        Type type = KClassImpl.this.getJClass().getGenericInterfaces()[indexOf];
                        Intrinsics.checkNotNullExpressionValue(type, "jClass.genericInterfaces[index]");
                        return type;
                    }
                    StringBuilder m586H2 = C1499a.m586H("No superclass of ");
                    m586H2.append(this.this$0);
                    m586H2.append(" in Java reflection for ");
                    m586H2.append(mo7311getDeclarationDescriptor);
                    throw new KotlinReflectionInternalError(m586H2.toString());
                }
            }));
        }
        if (!KotlinBuiltIns.isSpecialClassWithNoSupertypes(this.this$0.getDescriptor())) {
            boolean z = false;
            if (!arrayList.isEmpty()) {
                Iterator it = arrayList.iterator();
                while (it.hasNext()) {
                    ClassDescriptor classDescriptorForType = DescriptorUtils.getClassDescriptorForType(((KTypeImpl) it.next()).getType());
                    Intrinsics.checkNotNullExpressionValue(classDescriptorForType, "DescriptorUtils.getClassDescriptorForType(it.type)");
                    ClassKind kind = classDescriptorForType.getKind();
                    Intrinsics.checkNotNullExpressionValue(kind, "DescriptorUtils.getClass…ptorForType(it.type).kind");
                    if (!(kind == ClassKind.INTERFACE || kind == ClassKind.ANNOTATION_CLASS)) {
                        break;
                    }
                }
            }
            z = true;
            if (z) {
                SimpleType anyType = DescriptorUtilsKt.getBuiltIns(this.this$0.getDescriptor()).getAnyType();
                Intrinsics.checkNotNullExpressionValue(anyType, "descriptor.builtIns.anyType");
                arrayList.add(new KTypeImpl(anyType, new Function0<Type>() { // from class: kotlin.reflect.jvm.internal.KClassImpl$Data$supertypes$2.3
                    @Override // kotlin.jvm.functions.Function0
                    @NotNull
                    public final Type invoke() {
                        return Object.class;
                    }
                }));
            }
        }
        return CollectionsKt.compact(arrayList);
    }
}
