package kotlin.reflect.jvm.internal;

import androidx.exifinterface.media.ExifInterface;
import java.lang.annotation.Annotation;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.collections.CollectionsKt__CollectionsKt;
import kotlin.collections.CollectionsKt__IterablesKt;
import kotlin.collections.CollectionsKt___CollectionsKt;
import kotlin.jvm.JvmClassMappingKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.PropertyReference1Impl;
import kotlin.jvm.internal.Reflection;
import kotlin.jvm.internal.TypeIntrinsics;
import kotlin.reflect.KCallable;
import kotlin.reflect.KClass;
import kotlin.reflect.KFunction;
import kotlin.reflect.KProperty;
import kotlin.reflect.KType;
import kotlin.reflect.KTypeParameter;
import kotlin.reflect.KVisibility;
import kotlin.reflect.jvm.internal.KClassImpl;
import kotlin.reflect.jvm.internal.KDeclarationContainerImpl;
import kotlin.reflect.jvm.internal.ReflectProperties;
import kotlin.reflect.jvm.internal.impl.builtins.CompanionObjectMapping;
import kotlin.reflect.jvm.internal.impl.builtins.CompanionObjectMappingUtilsKt;
import kotlin.reflect.jvm.internal.impl.descriptors.ClassConstructorDescriptor;
import kotlin.reflect.jvm.internal.impl.descriptors.ClassDescriptor;
import kotlin.reflect.jvm.internal.impl.descriptors.ClassKind;
import kotlin.reflect.jvm.internal.impl.descriptors.ConstructorDescriptor;
import kotlin.reflect.jvm.internal.impl.descriptors.DeclarationDescriptor;
import kotlin.reflect.jvm.internal.impl.descriptors.DescriptorVisibility;
import kotlin.reflect.jvm.internal.impl.descriptors.FindClassInModuleKt;
import kotlin.reflect.jvm.internal.impl.descriptors.FunctionDescriptor;
import kotlin.reflect.jvm.internal.impl.descriptors.Modality;
import kotlin.reflect.jvm.internal.impl.descriptors.PropertyDescriptor;
import kotlin.reflect.jvm.internal.impl.descriptors.TypeParameterDescriptor;
import kotlin.reflect.jvm.internal.impl.descriptors.runtime.components.ReflectKotlinClass;
import kotlin.reflect.jvm.internal.impl.descriptors.runtime.components.RuntimeModuleData;
import kotlin.reflect.jvm.internal.impl.descriptors.runtime.structure.ReflectClassUtilKt;
import kotlin.reflect.jvm.internal.impl.incremental.components.NoLookupLocation;
import kotlin.reflect.jvm.internal.impl.load.kotlin.header.KotlinClassHeader;
import kotlin.reflect.jvm.internal.impl.metadata.ProtoBuf;
import kotlin.reflect.jvm.internal.impl.metadata.deserialization.ProtoBufUtilKt;
import kotlin.reflect.jvm.internal.impl.metadata.jvm.JvmProtoBuf;
import kotlin.reflect.jvm.internal.impl.name.ClassId;
import kotlin.reflect.jvm.internal.impl.name.FqName;
import kotlin.reflect.jvm.internal.impl.name.Name;
import kotlin.reflect.jvm.internal.impl.protobuf.GeneratedMessageLite;
import kotlin.reflect.jvm.internal.impl.resolve.DescriptorUtils;
import kotlin.reflect.jvm.internal.impl.resolve.scopes.MemberScope;
import kotlin.reflect.jvm.internal.impl.resolve.scopes.ResolutionScope;
import kotlin.reflect.jvm.internal.impl.serialization.deserialization.descriptors.DeserializedClassDescriptor;
import kotlin.text.StringsKt__StringsJVMKt;
import kotlin.text.StringsKt__StringsKt;
import kotlin.text.Typography;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000¾\u0001\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0001\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u001e\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\b\n\u0002\b\u0004\n\u0002\u0010\u000b\n\u0002\b\u0006\n\u0002\u0010\u000e\n\u0002\b\u0006\n\u0002\u0010 \n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\u001b\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\b\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\b\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\t\b\u0000\u0018\u0000*\b\b\u0000\u0010\u0002*\u00020\u00012\u00020\u00032\b\u0012\u0004\u0012\u00028\u00000\u00042\u00020\u00052\u00020\u0006:\u0001mB\u0015\u0012\f\u0010J\u001a\b\u0012\u0004\u0012\u00028\u00000I¢\u0006\u0004\bk\u0010lJ\u000f\u0010\b\u001a\u00020\u0007H\u0002¢\u0006\u0004\b\b\u0010\tJ\u001d\u0010\u000e\u001a\b\u0012\u0004\u0012\u00020\r0\f2\u0006\u0010\u000b\u001a\u00020\nH\u0016¢\u0006\u0004\b\u000e\u0010\u000fJ\u001d\u0010\u0011\u001a\b\u0012\u0004\u0012\u00020\u00100\f2\u0006\u0010\u000b\u001a\u00020\nH\u0016¢\u0006\u0004\b\u0011\u0010\u000fJ\u0019\u0010\u0014\u001a\u0004\u0018\u00010\r2\u0006\u0010\u0013\u001a\u00020\u0012H\u0016¢\u0006\u0004\b\u0014\u0010\u0015J\u0019\u0010\u0018\u001a\u00020\u00172\b\u0010\u0016\u001a\u0004\u0018\u00010\u0001H\u0016¢\u0006\u0004\b\u0018\u0010\u0019J\u001a\u0010\u001b\u001a\u00020\u00172\b\u0010\u001a\u001a\u0004\u0018\u00010\u0001H\u0096\u0002¢\u0006\u0004\b\u001b\u0010\u0019J\u000f\u0010\u001c\u001a\u00020\u0012H\u0016¢\u0006\u0004\b\u001c\u0010\u001dJ\u000f\u0010\u001f\u001a\u00020\u001eH\u0016¢\u0006\u0004\b\u001f\u0010 R\u001c\u0010!\u001a\u00020\u00178V@\u0016X\u0096\u0004¢\u0006\f\u0012\u0004\b#\u0010$\u001a\u0004\b!\u0010\"R$\u0010(\u001a\u0010\u0012\f\u0012\n\u0012\u0006\b\u0001\u0012\u00028\u00000\u00040%8V@\u0016X\u0096\u0004¢\u0006\u0006\u001a\u0004\b&\u0010'R\u001c\u0010,\u001a\b\u0012\u0004\u0012\u00020)0\f8V@\u0016X\u0096\u0004¢\u0006\u0006\u001a\u0004\b*\u0010+R\u0018\u00100\u001a\u0004\u0018\u00010-8V@\u0016X\u0096\u0004¢\u0006\u0006\u001a\u0004\b.\u0010/R\u001c\u00103\u001a\b\u0012\u0004\u0012\u0002010%8V@\u0016X\u0096\u0004¢\u0006\u0006\u001a\u0004\b2\u0010'R \u00106\u001a\f\u0012\b\u0012\u0006\u0012\u0002\b\u0003040\f8V@\u0016X\u0096\u0004¢\u0006\u0006\u001a\u0004\b5\u0010+R\u0016\u00107\u001a\u00020\u00178V@\u0016X\u0096\u0004¢\u0006\u0006\u001a\u0004\b7\u0010\"R\u0018\u00109\u001a\u0004\u0018\u00010\u001e8V@\u0016X\u0096\u0004¢\u0006\u0006\u001a\u0004\b8\u0010 R\u001c\u0010<\u001a\b\u0012\u0004\u0012\u00020:0%8V@\u0016X\u0096\u0004¢\u0006\u0006\u001a\u0004\b;\u0010'R\u0016\u0010=\u001a\u00020\u00178V@\u0016X\u0096\u0004¢\u0006\u0006\u001a\u0004\b=\u0010\"R\u0018\u0010@\u001a\u0004\u0018\u00018\u00008V@\u0016X\u0096\u0004¢\u0006\u0006\u001a\u0004\b>\u0010?R\u0016\u0010A\u001a\u00020\u00178V@\u0016X\u0096\u0004¢\u0006\u0006\u001a\u0004\bA\u0010\"R\u0016\u0010B\u001a\u00020\u00178V@\u0016X\u0096\u0004¢\u0006\u0006\u001a\u0004\bB\u0010\"R\u001c\u0010E\u001a\b\u0012\u0004\u0012\u00020C0%8V@\u0016X\u0096\u0004¢\u0006\u0006\u001a\u0004\bD\u0010'R \u0010G\u001a\f\u0012\b\u0012\u0006\u0012\u0002\b\u00030\u00040\f8V@\u0016X\u0096\u0004¢\u0006\u0006\u001a\u0004\bF\u0010+R\u0016\u0010H\u001a\u00020\u00178V@\u0016X\u0096\u0004¢\u0006\u0006\u001a\u0004\bH\u0010\"R\"\u0010J\u001a\b\u0012\u0004\u0012\u00028\u00000I8\u0016@\u0016X\u0096\u0004¢\u0006\f\n\u0004\bJ\u0010K\u001a\u0004\bL\u0010MR\u0016\u0010N\u001a\u00020\u00178V@\u0016X\u0096\u0004¢\u0006\u0006\u001a\u0004\bN\u0010\"R\u0016\u0010O\u001a\u00020\u00178V@\u0016X\u0096\u0004¢\u0006\u0006\u001a\u0004\bO\u0010\"R\u0018\u0010Q\u001a\u0004\u0018\u00010\u001e8V@\u0016X\u0096\u0004¢\u0006\u0006\u001a\u0004\bP\u0010 R;\u0010U\u001a$\u0012 \u0012\u001e T*\u000e\u0018\u00010SR\b\u0012\u0004\u0012\u00028\u00000\u00000SR\b\u0012\u0004\u0012\u00028\u00000\u00000R8\u0006@\u0006¢\u0006\f\n\u0004\bU\u0010V\u001a\u0004\bW\u0010XR\u0016\u0010Y\u001a\u00020\u00178V@\u0016X\u0096\u0004¢\u0006\u0006\u001a\u0004\bY\u0010\"R\"\u0010\\\u001a\u000e\u0012\n\u0012\b\u0012\u0004\u0012\u00028\u00000Z0\f8V@\u0016X\u0096\u0004¢\u0006\u0006\u001a\u0004\b[\u0010+R\u0016\u0010`\u001a\u00020]8B@\u0002X\u0082\u0004¢\u0006\u0006\u001a\u0004\b^\u0010_R\u0016\u0010d\u001a\u00020a8V@\u0016X\u0096\u0004¢\u0006\u0006\u001a\u0004\bb\u0010cR\u0016\u0010h\u001a\u00020e8@@\u0000X\u0080\u0004¢\u0006\u0006\u001a\u0004\bf\u0010gR\u0016\u0010j\u001a\u00020e8@@\u0000X\u0080\u0004¢\u0006\u0006\u001a\u0004\bi\u0010g¨\u0006n"}, m5311d2 = {"Lkotlin/reflect/jvm/internal/KClassImpl;", "", ExifInterface.GPS_DIRECTION_TRUE, "Lkotlin/reflect/jvm/internal/KDeclarationContainerImpl;", "Lkotlin/reflect/KClass;", "Lkotlin/reflect/jvm/internal/KClassifierImpl;", "Lkotlin/reflect/jvm/internal/KTypeParameterOwnerImpl;", "", "reportUnresolvedClass", "()Ljava/lang/Void;", "Lkotlin/reflect/jvm/internal/impl/name/Name;", "name", "", "Lkotlin/reflect/jvm/internal/impl/descriptors/PropertyDescriptor;", "getProperties", "(Lkotlin/reflect/jvm/internal/impl/name/Name;)Ljava/util/Collection;", "Lkotlin/reflect/jvm/internal/impl/descriptors/FunctionDescriptor;", "getFunctions", "", "index", "getLocalProperty", "(I)Lkotlin/reflect/jvm/internal/impl/descriptors/PropertyDescriptor;", "value", "", "isInstance", "(Ljava/lang/Object;)Z", "other", "equals", "hashCode", "()I", "", "toString", "()Ljava/lang/String;", "isValue", "()Z", "isValue$annotations", "()V", "", "getSealedSubclasses", "()Ljava/util/List;", "sealedSubclasses", "Lkotlin/reflect/jvm/internal/impl/descriptors/ConstructorDescriptor;", "getConstructorDescriptors", "()Ljava/util/Collection;", "constructorDescriptors", "Lkotlin/reflect/KVisibility;", "getVisibility", "()Lkotlin/reflect/KVisibility;", "visibility", "", "getAnnotations", "annotations", "Lkotlin/reflect/KCallable;", "getMembers", "members", "isInner", "getSimpleName", "simpleName", "Lkotlin/reflect/KType;", "getSupertypes", "supertypes", "isSealed", "getObjectInstance", "()Ljava/lang/Object;", "objectInstance", "isCompanion", "isFinal", "Lkotlin/reflect/KTypeParameter;", "getTypeParameters", "typeParameters", "getNestedClasses", "nestedClasses", "isOpen", "Ljava/lang/Class;", "jClass", "Ljava/lang/Class;", "getJClass", "()Ljava/lang/Class;", "isFun", "isData", "getQualifiedName", "qualifiedName", "Lkotlin/reflect/jvm/internal/ReflectProperties$LazyVal;", "Lkotlin/reflect/jvm/internal/KClassImpl$Data;", "kotlin.jvm.PlatformType", "data", "Lkotlin/reflect/jvm/internal/ReflectProperties$LazyVal;", "getData", "()Lkotlin/reflect/jvm/internal/ReflectProperties$LazyVal;", "isAbstract", "Lkotlin/reflect/KFunction;", "getConstructors", "constructors", "Lkotlin/reflect/jvm/internal/impl/name/ClassId;", "getClassId", "()Lorg/jetbrains/kotlin/name/ClassId;", "classId", "Lkotlin/reflect/jvm/internal/impl/descriptors/ClassDescriptor;", "getDescriptor", "()Lorg/jetbrains/kotlin/descriptors/ClassDescriptor;", "descriptor", "Lkotlin/reflect/jvm/internal/impl/resolve/scopes/MemberScope;", "getMemberScope$kotlin_reflection", "()Lorg/jetbrains/kotlin/resolve/scopes/MemberScope;", "memberScope", "getStaticScope$kotlin_reflection", "staticScope", "<init>", "(Ljava/lang/Class;)V", "Data", "kotlin-reflection"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes.dex */
public final class KClassImpl<T> extends KDeclarationContainerImpl implements KClass<T>, KClassifierImpl, KTypeParameterOwnerImpl {

    @NotNull
    private final ReflectProperties.LazyVal<KClassImpl<T>.Data> data;

    @NotNull
    private final Class<T> jClass;

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000Z\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0002\b\u0002\n\u0002\u0010\u001e\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010 \n\u0002\u0010\u001b\n\u0002\b\b\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u000e\n\u0002\u0018\u0002\n\u0002\b\u001e\b\u0086\u0004\u0018\u00002\u00060\u0001R\u00020\u0002B\u0007¢\u0006\u0004\bQ\u0010RJ\u001b\u0010\u0006\u001a\u00020\u00052\n\u0010\u0004\u001a\u0006\u0012\u0002\b\u00030\u0003H\u0002¢\u0006\u0004\b\u0006\u0010\u0007R'\u0010\u000e\u001a\f\u0012\b\u0012\u0006\u0012\u0002\b\u00030\t0\b8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\n\u0010\u000b\u001a\u0004\b\f\u0010\rR\u001d\u0010\u0013\u001a\u00020\u000f8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u0010\u0010\u000b\u001a\u0004\b\u0011\u0010\u0012R'\u0010\u0017\u001a\f\u0012\b\u0012\u0006\u0012\u0002\b\u00030\u00140\b8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u0015\u0010\u000b\u001a\u0004\b\u0016\u0010\rR#\u0010\u001d\u001a\b\u0012\u0004\u0012\u00020\u00190\u00188F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u001a\u0010\u000b\u001a\u0004\b\u001b\u0010\u001cR\u001f\u0010!\u001a\u0004\u0018\u00010\u00058F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u001e\u0010\u000b\u001a\u0004\b\u001f\u0010 R#\u0010%\u001a\b\u0012\u0004\u0012\u00020\"0\u00188F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b#\u0010\u000b\u001a\u0004\b$\u0010\u001cR/\u0010+\u001a\u000e\u0012\n\u0012\b\u0012\u0004\u0012\u00028\u00000&0\b8F@\u0006X\u0086\u0084\u0002¢\u0006\u0012\n\u0004\b'\u0010\u000b\u0012\u0004\b)\u0010*\u001a\u0004\b(\u0010\rR+\u0010.\u001a\u0010\u0012\f\u0012\n\u0012\u0006\b\u0001\u0012\u00028\u00000\t0\u00188F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b,\u0010\u000b\u001a\u0004\b-\u0010\u001cR'\u00101\u001a\f\u0012\b\u0012\u0006\u0012\u0002\b\u00030\u00140\b8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b/\u0010\u000b\u001a\u0004\b0\u0010\rR\u001f\u00104\u001a\u0004\u0018\u00010\u00058F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b2\u0010\u000b\u001a\u0004\b3\u0010 R#\u00108\u001a\b\u0012\u0004\u0012\u0002050\u00188F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b6\u0010\u000b\u001a\u0004\b7\u0010\u001cR'\u0010;\u001a\f\u0012\b\u0012\u0006\u0012\u0002\b\u00030\u00140\b8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b9\u0010\u000b\u001a\u0004\b:\u0010\rR'\u0010>\u001a\f\u0012\b\u0012\u0006\u0012\u0002\b\u00030\u00140\b8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b<\u0010\u000b\u001a\u0004\b=\u0010\rR'\u0010A\u001a\f\u0012\b\u0012\u0006\u0012\u0002\b\u00030\u00140\b8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b?\u0010\u000b\u001a\u0004\b@\u0010\rR'\u0010D\u001a\f\u0012\b\u0012\u0006\u0012\u0002\b\u00030\u00140\b8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bB\u0010\u000b\u001a\u0004\bC\u0010\rR%\u0010J\u001a\u0004\u0018\u00018\u00008F@\u0006X\u0086\u0084\u0002¢\u0006\u0012\n\u0004\bE\u0010F\u0012\u0004\bI\u0010*\u001a\u0004\bG\u0010HR'\u0010M\u001a\f\u0012\b\u0012\u0006\u0012\u0002\b\u00030\u00140\b8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bK\u0010\u000b\u001a\u0004\bL\u0010\rR'\u0010P\u001a\f\u0012\b\u0012\u0006\u0012\u0002\b\u00030\u00140\b8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bN\u0010\u000b\u001a\u0004\bO\u0010\r¨\u0006S"}, m5311d2 = {"Lkotlin/reflect/jvm/internal/KClassImpl$Data;", "Lkotlin/reflect/jvm/internal/KDeclarationContainerImpl$Data;", "Lkotlin/reflect/jvm/internal/KDeclarationContainerImpl;", "Ljava/lang/Class;", "jClass", "", "calculateLocalClassName", "(Ljava/lang/Class;)Ljava/lang/String;", "", "Lkotlin/reflect/KClass;", "nestedClasses$delegate", "Lkotlin/reflect/jvm/internal/ReflectProperties$LazySoftVal;", "getNestedClasses", "()Ljava/util/Collection;", "nestedClasses", "Lkotlin/reflect/jvm/internal/impl/descriptors/ClassDescriptor;", "descriptor$delegate", "getDescriptor", "()Lorg/jetbrains/kotlin/descriptors/ClassDescriptor;", "descriptor", "Lkotlin/reflect/jvm/internal/KCallableImpl;", "inheritedStaticMembers$delegate", "getInheritedStaticMembers", "inheritedStaticMembers", "", "", "annotations$delegate", "getAnnotations", "()Ljava/util/List;", "annotations", "qualifiedName$delegate", "getQualifiedName", "()Ljava/lang/String;", "qualifiedName", "Lkotlin/reflect/KType;", "supertypes$delegate", "getSupertypes", "supertypes", "Lkotlin/reflect/KFunction;", "constructors$delegate", "getConstructors", "getConstructors$annotations", "()V", "constructors", "sealedSubclasses$delegate", "getSealedSubclasses", "sealedSubclasses", "declaredNonStaticMembers$delegate", "getDeclaredNonStaticMembers", "declaredNonStaticMembers", "simpleName$delegate", "getSimpleName", "simpleName", "Lkotlin/reflect/KTypeParameter;", "typeParameters$delegate", "getTypeParameters", "typeParameters", "allNonStaticMembers$delegate", "getAllNonStaticMembers", "allNonStaticMembers", "declaredStaticMembers$delegate", "getDeclaredStaticMembers", "declaredStaticMembers", "inheritedNonStaticMembers$delegate", "getInheritedNonStaticMembers", "inheritedNonStaticMembers", "allMembers$delegate", "getAllMembers", "allMembers", "objectInstance$delegate", "Lkotlin/reflect/jvm/internal/ReflectProperties$LazyVal;", "getObjectInstance", "()Ljava/lang/Object;", "getObjectInstance$annotations", "objectInstance", "allStaticMembers$delegate", "getAllStaticMembers", "allStaticMembers", "declaredMembers$delegate", "getDeclaredMembers", "declaredMembers", "<init>", "(Lkotlin/reflect/jvm/internal/KClassImpl;)V", "kotlin-reflection"}, m5312k = 1, m5313mv = {1, 5, 1})
    public final class Data extends KDeclarationContainerImpl.Data {
        public static final /* synthetic */ KProperty[] $$delegatedProperties = {Reflection.property1(new PropertyReference1Impl(Reflection.getOrCreateKotlinClass(Data.class), "descriptor", "getDescriptor()Lorg/jetbrains/kotlin/descriptors/ClassDescriptor;")), Reflection.property1(new PropertyReference1Impl(Reflection.getOrCreateKotlinClass(Data.class), "annotations", "getAnnotations()Ljava/util/List;")), Reflection.property1(new PropertyReference1Impl(Reflection.getOrCreateKotlinClass(Data.class), "simpleName", "getSimpleName()Ljava/lang/String;")), Reflection.property1(new PropertyReference1Impl(Reflection.getOrCreateKotlinClass(Data.class), "qualifiedName", "getQualifiedName()Ljava/lang/String;")), Reflection.property1(new PropertyReference1Impl(Reflection.getOrCreateKotlinClass(Data.class), "constructors", "getConstructors()Ljava/util/Collection;")), Reflection.property1(new PropertyReference1Impl(Reflection.getOrCreateKotlinClass(Data.class), "nestedClasses", "getNestedClasses()Ljava/util/Collection;")), Reflection.property1(new PropertyReference1Impl(Reflection.getOrCreateKotlinClass(Data.class), "objectInstance", "getObjectInstance()Ljava/lang/Object;")), Reflection.property1(new PropertyReference1Impl(Reflection.getOrCreateKotlinClass(Data.class), "typeParameters", "getTypeParameters()Ljava/util/List;")), Reflection.property1(new PropertyReference1Impl(Reflection.getOrCreateKotlinClass(Data.class), "supertypes", "getSupertypes()Ljava/util/List;")), Reflection.property1(new PropertyReference1Impl(Reflection.getOrCreateKotlinClass(Data.class), "sealedSubclasses", "getSealedSubclasses()Ljava/util/List;")), Reflection.property1(new PropertyReference1Impl(Reflection.getOrCreateKotlinClass(Data.class), "declaredNonStaticMembers", "getDeclaredNonStaticMembers()Ljava/util/Collection;")), Reflection.property1(new PropertyReference1Impl(Reflection.getOrCreateKotlinClass(Data.class), "declaredStaticMembers", "getDeclaredStaticMembers()Ljava/util/Collection;")), Reflection.property1(new PropertyReference1Impl(Reflection.getOrCreateKotlinClass(Data.class), "inheritedNonStaticMembers", "getInheritedNonStaticMembers()Ljava/util/Collection;")), Reflection.property1(new PropertyReference1Impl(Reflection.getOrCreateKotlinClass(Data.class), "inheritedStaticMembers", "getInheritedStaticMembers()Ljava/util/Collection;")), Reflection.property1(new PropertyReference1Impl(Reflection.getOrCreateKotlinClass(Data.class), "allNonStaticMembers", "getAllNonStaticMembers()Ljava/util/Collection;")), Reflection.property1(new PropertyReference1Impl(Reflection.getOrCreateKotlinClass(Data.class), "allStaticMembers", "getAllStaticMembers()Ljava/util/Collection;")), Reflection.property1(new PropertyReference1Impl(Reflection.getOrCreateKotlinClass(Data.class), "declaredMembers", "getDeclaredMembers()Ljava/util/Collection;")), Reflection.property1(new PropertyReference1Impl(Reflection.getOrCreateKotlinClass(Data.class), "allMembers", "getAllMembers()Ljava/util/Collection;"))};

        /* renamed from: allMembers$delegate, reason: from kotlin metadata */
        @NotNull
        private final ReflectProperties.LazySoftVal allMembers;

        /* renamed from: allNonStaticMembers$delegate, reason: from kotlin metadata */
        @NotNull
        private final ReflectProperties.LazySoftVal allNonStaticMembers;

        /* renamed from: allStaticMembers$delegate, reason: from kotlin metadata */
        @NotNull
        private final ReflectProperties.LazySoftVal allStaticMembers;

        /* renamed from: annotations$delegate, reason: from kotlin metadata */
        @NotNull
        private final ReflectProperties.LazySoftVal annotations;

        /* renamed from: constructors$delegate, reason: from kotlin metadata */
        @NotNull
        private final ReflectProperties.LazySoftVal constructors;

        /* renamed from: declaredMembers$delegate, reason: from kotlin metadata */
        @NotNull
        private final ReflectProperties.LazySoftVal declaredMembers;

        /* renamed from: declaredNonStaticMembers$delegate, reason: from kotlin metadata */
        @NotNull
        private final ReflectProperties.LazySoftVal declaredNonStaticMembers;

        /* renamed from: declaredStaticMembers$delegate, reason: from kotlin metadata */
        private final ReflectProperties.LazySoftVal declaredStaticMembers;

        /* renamed from: descriptor$delegate, reason: from kotlin metadata */
        @NotNull
        private final ReflectProperties.LazySoftVal descriptor;

        /* renamed from: inheritedNonStaticMembers$delegate, reason: from kotlin metadata */
        private final ReflectProperties.LazySoftVal inheritedNonStaticMembers;

        /* renamed from: inheritedStaticMembers$delegate, reason: from kotlin metadata */
        private final ReflectProperties.LazySoftVal inheritedStaticMembers;

        /* renamed from: nestedClasses$delegate, reason: from kotlin metadata */
        @NotNull
        private final ReflectProperties.LazySoftVal nestedClasses;

        /* renamed from: objectInstance$delegate, reason: from kotlin metadata */
        @Nullable
        private final ReflectProperties.LazyVal objectInstance;

        /* renamed from: qualifiedName$delegate, reason: from kotlin metadata */
        @Nullable
        private final ReflectProperties.LazySoftVal qualifiedName;

        /* renamed from: sealedSubclasses$delegate, reason: from kotlin metadata */
        @NotNull
        private final ReflectProperties.LazySoftVal sealedSubclasses;

        /* renamed from: simpleName$delegate, reason: from kotlin metadata */
        @Nullable
        private final ReflectProperties.LazySoftVal simpleName;

        /* renamed from: supertypes$delegate, reason: from kotlin metadata */
        @NotNull
        private final ReflectProperties.LazySoftVal supertypes;

        /* renamed from: typeParameters$delegate, reason: from kotlin metadata */
        @NotNull
        private final ReflectProperties.LazySoftVal typeParameters;

        public Data() {
            super();
            this.descriptor = ReflectProperties.lazySoft(new Function0<ClassDescriptor>() { // from class: kotlin.reflect.jvm.internal.KClassImpl$Data$descriptor$2
                {
                    super(0);
                }

                @Override // kotlin.jvm.functions.Function0
                public final ClassDescriptor invoke() {
                    ClassId classId;
                    classId = KClassImpl.this.getClassId();
                    RuntimeModuleData moduleData = ((KClassImpl.Data) KClassImpl.this.getData().invoke()).getModuleData();
                    ClassDescriptor deserializeClass = classId.isLocal() ? moduleData.getDeserialization().deserializeClass(classId) : FindClassInModuleKt.findClassAcrossModuleDependencies(moduleData.getModule(), classId);
                    if (deserializeClass != null) {
                        return deserializeClass;
                    }
                    KClassImpl.this.reportUnresolvedClass();
                    throw null;
                }
            });
            this.annotations = ReflectProperties.lazySoft(new Function0<List<? extends Annotation>>() { // from class: kotlin.reflect.jvm.internal.KClassImpl$Data$annotations$2
                {
                    super(0);
                }

                @Override // kotlin.jvm.functions.Function0
                public final List<? extends Annotation> invoke() {
                    return UtilKt.computeAnnotations(KClassImpl.Data.this.getDescriptor());
                }
            });
            this.simpleName = ReflectProperties.lazySoft(new Function0<String>() { // from class: kotlin.reflect.jvm.internal.KClassImpl$Data$simpleName$2
                {
                    super(0);
                }

                @Override // kotlin.jvm.functions.Function0
                @Nullable
                public final String invoke() {
                    ClassId classId;
                    String calculateLocalClassName;
                    if (KClassImpl.this.getJClass().isAnonymousClass()) {
                        return null;
                    }
                    classId = KClassImpl.this.getClassId();
                    if (classId.isLocal()) {
                        KClassImpl.Data data = KClassImpl.Data.this;
                        calculateLocalClassName = data.calculateLocalClassName(KClassImpl.this.getJClass());
                        return calculateLocalClassName;
                    }
                    String asString = classId.getShortClassName().asString();
                    Intrinsics.checkNotNullExpressionValue(asString, "classId.shortClassName.asString()");
                    return asString;
                }
            });
            this.qualifiedName = ReflectProperties.lazySoft(new Function0<String>() { // from class: kotlin.reflect.jvm.internal.KClassImpl$Data$qualifiedName$2
                {
                    super(0);
                }

                @Override // kotlin.jvm.functions.Function0
                @Nullable
                public final String invoke() {
                    ClassId classId;
                    if (KClassImpl.this.getJClass().isAnonymousClass()) {
                        return null;
                    }
                    classId = KClassImpl.this.getClassId();
                    if (classId.isLocal()) {
                        return null;
                    }
                    return classId.asSingleFqName().asString();
                }
            });
            this.constructors = ReflectProperties.lazySoft(new Function0<List<? extends KFunction<? extends T>>>() { // from class: kotlin.reflect.jvm.internal.KClassImpl$Data$constructors$2
                {
                    super(0);
                }

                @Override // kotlin.jvm.functions.Function0
                public final List<KFunction<T>> invoke() {
                    Collection<ConstructorDescriptor> constructorDescriptors = KClassImpl.this.getConstructorDescriptors();
                    ArrayList arrayList = new ArrayList(CollectionsKt__IterablesKt.collectionSizeOrDefault(constructorDescriptors, 10));
                    Iterator<T> it = constructorDescriptors.iterator();
                    while (it.hasNext()) {
                        arrayList.add(new KFunctionImpl(KClassImpl.this, (ConstructorDescriptor) it.next()));
                    }
                    return arrayList;
                }
            });
            this.nestedClasses = ReflectProperties.lazySoft(new Function0<List<? extends KClassImpl<? extends Object>>>() { // from class: kotlin.reflect.jvm.internal.KClassImpl$Data$nestedClasses$2
                {
                    super(0);
                }

                @Override // kotlin.jvm.functions.Function0
                public final List<? extends KClassImpl<? extends Object>> invoke() {
                    Collection contributedDescriptors$default = ResolutionScope.DefaultImpls.getContributedDescriptors$default(KClassImpl.Data.this.getDescriptor().getUnsubstitutedInnerClassesScope(), null, null, 3, null);
                    ArrayList<DeclarationDescriptor> arrayList = new ArrayList();
                    for (Object obj : contributedDescriptors$default) {
                        if (!DescriptorUtils.isEnumEntry((DeclarationDescriptor) obj)) {
                            arrayList.add(obj);
                        }
                    }
                    ArrayList arrayList2 = new ArrayList();
                    for (DeclarationDescriptor declarationDescriptor : arrayList) {
                        Objects.requireNonNull(declarationDescriptor, "null cannot be cast to non-null type org.jetbrains.kotlin.descriptors.ClassDescriptor");
                        Class<?> javaClass = UtilKt.toJavaClass((ClassDescriptor) declarationDescriptor);
                        KClassImpl kClassImpl = javaClass != null ? new KClassImpl(javaClass) : null;
                        if (kClassImpl != null) {
                            arrayList2.add(kClassImpl);
                        }
                    }
                    return arrayList2;
                }
            });
            this.objectInstance = ReflectProperties.lazy(new Function0<T>() { // from class: kotlin.reflect.jvm.internal.KClassImpl$Data$objectInstance$2
                {
                    super(0);
                }

                @Override // kotlin.jvm.functions.Function0
                @Nullable
                public final T invoke() {
                    ClassDescriptor descriptor = KClassImpl.Data.this.getDescriptor();
                    if (descriptor.getKind() != ClassKind.OBJECT) {
                        return null;
                    }
                    T t = (T) ((!descriptor.isCompanionObject() || CompanionObjectMappingUtilsKt.isMappedIntrinsicCompanionObject(CompanionObjectMapping.INSTANCE, descriptor)) ? KClassImpl.this.getJClass().getDeclaredField("INSTANCE") : KClassImpl.this.getJClass().getEnclosingClass().getDeclaredField(descriptor.getName().asString())).get(null);
                    Objects.requireNonNull(t, "null cannot be cast to non-null type T");
                    return t;
                }
            });
            this.typeParameters = ReflectProperties.lazySoft(new Function0<List<? extends KTypeParameterImpl>>() { // from class: kotlin.reflect.jvm.internal.KClassImpl$Data$typeParameters$2
                {
                    super(0);
                }

                @Override // kotlin.jvm.functions.Function0
                public final List<? extends KTypeParameterImpl> invoke() {
                    List<TypeParameterDescriptor> declaredTypeParameters = KClassImpl.Data.this.getDescriptor().getDeclaredTypeParameters();
                    Intrinsics.checkNotNullExpressionValue(declaredTypeParameters, "descriptor.declaredTypeParameters");
                    ArrayList arrayList = new ArrayList(CollectionsKt__IterablesKt.collectionSizeOrDefault(declaredTypeParameters, 10));
                    for (TypeParameterDescriptor descriptor : declaredTypeParameters) {
                        KClassImpl kClassImpl = KClassImpl.this;
                        Intrinsics.checkNotNullExpressionValue(descriptor, "descriptor");
                        arrayList.add(new KTypeParameterImpl(kClassImpl, descriptor));
                    }
                    return arrayList;
                }
            });
            this.supertypes = ReflectProperties.lazySoft(new KClassImpl$Data$supertypes$2(this));
            this.sealedSubclasses = ReflectProperties.lazySoft(new Function0<List<? extends KClassImpl<? extends T>>>() { // from class: kotlin.reflect.jvm.internal.KClassImpl$Data$sealedSubclasses$2
                {
                    super(0);
                }

                @Override // kotlin.jvm.functions.Function0
                public final List<KClassImpl<? extends T>> invoke() {
                    Collection<ClassDescriptor> sealedSubclasses = KClassImpl.Data.this.getDescriptor().getSealedSubclasses();
                    Intrinsics.checkNotNullExpressionValue(sealedSubclasses, "descriptor.sealedSubclasses");
                    ArrayList arrayList = new ArrayList();
                    for (ClassDescriptor classDescriptor : sealedSubclasses) {
                        Objects.requireNonNull(classDescriptor, "null cannot be cast to non-null type org.jetbrains.kotlin.descriptors.ClassDescriptor");
                        Class<?> javaClass = UtilKt.toJavaClass(classDescriptor);
                        KClassImpl kClassImpl = javaClass != null ? new KClassImpl(javaClass) : null;
                        if (kClassImpl != null) {
                            arrayList.add(kClassImpl);
                        }
                    }
                    return arrayList;
                }
            });
            this.declaredNonStaticMembers = ReflectProperties.lazySoft(new Function0<Collection<? extends KCallableImpl<?>>>() { // from class: kotlin.reflect.jvm.internal.KClassImpl$Data$declaredNonStaticMembers$2
                {
                    super(0);
                }

                @Override // kotlin.jvm.functions.Function0
                public final Collection<? extends KCallableImpl<?>> invoke() {
                    KClassImpl kClassImpl = KClassImpl.this;
                    return kClassImpl.getMembers(kClassImpl.getMemberScope$kotlin_reflection(), KDeclarationContainerImpl.MemberBelonginess.DECLARED);
                }
            });
            this.declaredStaticMembers = ReflectProperties.lazySoft(new Function0<Collection<? extends KCallableImpl<?>>>() { // from class: kotlin.reflect.jvm.internal.KClassImpl$Data$declaredStaticMembers$2
                {
                    super(0);
                }

                @Override // kotlin.jvm.functions.Function0
                public final Collection<? extends KCallableImpl<?>> invoke() {
                    KClassImpl kClassImpl = KClassImpl.this;
                    return kClassImpl.getMembers(kClassImpl.getStaticScope$kotlin_reflection(), KDeclarationContainerImpl.MemberBelonginess.DECLARED);
                }
            });
            this.inheritedNonStaticMembers = ReflectProperties.lazySoft(new Function0<Collection<? extends KCallableImpl<?>>>() { // from class: kotlin.reflect.jvm.internal.KClassImpl$Data$inheritedNonStaticMembers$2
                {
                    super(0);
                }

                @Override // kotlin.jvm.functions.Function0
                public final Collection<? extends KCallableImpl<?>> invoke() {
                    KClassImpl kClassImpl = KClassImpl.this;
                    return kClassImpl.getMembers(kClassImpl.getMemberScope$kotlin_reflection(), KDeclarationContainerImpl.MemberBelonginess.INHERITED);
                }
            });
            this.inheritedStaticMembers = ReflectProperties.lazySoft(new Function0<Collection<? extends KCallableImpl<?>>>() { // from class: kotlin.reflect.jvm.internal.KClassImpl$Data$inheritedStaticMembers$2
                {
                    super(0);
                }

                @Override // kotlin.jvm.functions.Function0
                public final Collection<? extends KCallableImpl<?>> invoke() {
                    KClassImpl kClassImpl = KClassImpl.this;
                    return kClassImpl.getMembers(kClassImpl.getStaticScope$kotlin_reflection(), KDeclarationContainerImpl.MemberBelonginess.INHERITED);
                }
            });
            this.allNonStaticMembers = ReflectProperties.lazySoft(new Function0<List<? extends KCallableImpl<?>>>() { // from class: kotlin.reflect.jvm.internal.KClassImpl$Data$allNonStaticMembers$2
                {
                    super(0);
                }

                @Override // kotlin.jvm.functions.Function0
                public final List<? extends KCallableImpl<?>> invoke() {
                    Collection inheritedNonStaticMembers;
                    Collection<KCallableImpl<?>> declaredNonStaticMembers = KClassImpl.Data.this.getDeclaredNonStaticMembers();
                    inheritedNonStaticMembers = KClassImpl.Data.this.getInheritedNonStaticMembers();
                    return CollectionsKt___CollectionsKt.plus((Collection) declaredNonStaticMembers, (Iterable) inheritedNonStaticMembers);
                }
            });
            this.allStaticMembers = ReflectProperties.lazySoft(new Function0<List<? extends KCallableImpl<?>>>() { // from class: kotlin.reflect.jvm.internal.KClassImpl$Data$allStaticMembers$2
                {
                    super(0);
                }

                @Override // kotlin.jvm.functions.Function0
                public final List<? extends KCallableImpl<?>> invoke() {
                    Collection declaredStaticMembers;
                    Collection inheritedStaticMembers;
                    declaredStaticMembers = KClassImpl.Data.this.getDeclaredStaticMembers();
                    inheritedStaticMembers = KClassImpl.Data.this.getInheritedStaticMembers();
                    return CollectionsKt___CollectionsKt.plus(declaredStaticMembers, (Iterable) inheritedStaticMembers);
                }
            });
            this.declaredMembers = ReflectProperties.lazySoft(new Function0<List<? extends KCallableImpl<?>>>() { // from class: kotlin.reflect.jvm.internal.KClassImpl$Data$declaredMembers$2
                {
                    super(0);
                }

                @Override // kotlin.jvm.functions.Function0
                public final List<? extends KCallableImpl<?>> invoke() {
                    Collection declaredStaticMembers;
                    Collection<KCallableImpl<?>> declaredNonStaticMembers = KClassImpl.Data.this.getDeclaredNonStaticMembers();
                    declaredStaticMembers = KClassImpl.Data.this.getDeclaredStaticMembers();
                    return CollectionsKt___CollectionsKt.plus((Collection) declaredNonStaticMembers, (Iterable) declaredStaticMembers);
                }
            });
            this.allMembers = ReflectProperties.lazySoft(new Function0<List<? extends KCallableImpl<?>>>() { // from class: kotlin.reflect.jvm.internal.KClassImpl$Data$allMembers$2
                {
                    super(0);
                }

                @Override // kotlin.jvm.functions.Function0
                public final List<? extends KCallableImpl<?>> invoke() {
                    return CollectionsKt___CollectionsKt.plus((Collection) KClassImpl.Data.this.getAllNonStaticMembers(), (Iterable) KClassImpl.Data.this.getAllStaticMembers());
                }
            });
        }

        /* JADX INFO: Access modifiers changed from: private */
        public final String calculateLocalClassName(Class<?> jClass) {
            String name = jClass.getSimpleName();
            Method enclosingMethod = jClass.getEnclosingMethod();
            if (enclosingMethod != null) {
                Intrinsics.checkNotNullExpressionValue(name, "name");
                return StringsKt__StringsKt.substringAfter$default(name, enclosingMethod.getName() + "$", (String) null, 2, (Object) null);
            }
            Constructor<?> enclosingConstructor = jClass.getEnclosingConstructor();
            if (enclosingConstructor == null) {
                Intrinsics.checkNotNullExpressionValue(name, "name");
                return StringsKt__StringsKt.substringAfter$default(name, Typography.dollar, (String) null, 2, (Object) null);
            }
            Intrinsics.checkNotNullExpressionValue(name, "name");
            return StringsKt__StringsKt.substringAfter$default(name, enclosingConstructor.getName() + "$", (String) null, 2, (Object) null);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public final Collection<KCallableImpl<?>> getDeclaredStaticMembers() {
            return (Collection) this.declaredStaticMembers.getValue(this, $$delegatedProperties[11]);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public final Collection<KCallableImpl<?>> getInheritedNonStaticMembers() {
            return (Collection) this.inheritedNonStaticMembers.getValue(this, $$delegatedProperties[12]);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public final Collection<KCallableImpl<?>> getInheritedStaticMembers() {
            return (Collection) this.inheritedStaticMembers.getValue(this, $$delegatedProperties[13]);
        }

        @NotNull
        public final Collection<KCallableImpl<?>> getAllMembers() {
            return (Collection) this.allMembers.getValue(this, $$delegatedProperties[17]);
        }

        @NotNull
        public final Collection<KCallableImpl<?>> getAllNonStaticMembers() {
            return (Collection) this.allNonStaticMembers.getValue(this, $$delegatedProperties[14]);
        }

        @NotNull
        public final Collection<KCallableImpl<?>> getAllStaticMembers() {
            return (Collection) this.allStaticMembers.getValue(this, $$delegatedProperties[15]);
        }

        @NotNull
        public final List<Annotation> getAnnotations() {
            return (List) this.annotations.getValue(this, $$delegatedProperties[1]);
        }

        @NotNull
        public final Collection<KFunction<T>> getConstructors() {
            return (Collection) this.constructors.getValue(this, $$delegatedProperties[4]);
        }

        @NotNull
        public final Collection<KCallableImpl<?>> getDeclaredMembers() {
            return (Collection) this.declaredMembers.getValue(this, $$delegatedProperties[16]);
        }

        @NotNull
        public final Collection<KCallableImpl<?>> getDeclaredNonStaticMembers() {
            return (Collection) this.declaredNonStaticMembers.getValue(this, $$delegatedProperties[10]);
        }

        @NotNull
        public final ClassDescriptor getDescriptor() {
            return (ClassDescriptor) this.descriptor.getValue(this, $$delegatedProperties[0]);
        }

        @NotNull
        public final Collection<KClass<?>> getNestedClasses() {
            return (Collection) this.nestedClasses.getValue(this, $$delegatedProperties[5]);
        }

        @Nullable
        public final T getObjectInstance() {
            return this.objectInstance.getValue(this, $$delegatedProperties[6]);
        }

        @Nullable
        public final String getQualifiedName() {
            return (String) this.qualifiedName.getValue(this, $$delegatedProperties[3]);
        }

        @NotNull
        public final List<KClass<? extends T>> getSealedSubclasses() {
            return (List) this.sealedSubclasses.getValue(this, $$delegatedProperties[9]);
        }

        @Nullable
        public final String getSimpleName() {
            return (String) this.simpleName.getValue(this, $$delegatedProperties[2]);
        }

        @NotNull
        public final List<KType> getSupertypes() {
            return (List) this.supertypes.getValue(this, $$delegatedProperties[8]);
        }

        @NotNull
        public final List<KTypeParameter> getTypeParameters() {
            return (List) this.typeParameters.getValue(this, $$delegatedProperties[7]);
        }
    }

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {}, m5311d2 = {}, m5312k = 3, m5313mv = {1, 5, 1})
    public final /* synthetic */ class WhenMappings {
        public static final /* synthetic */ int[] $EnumSwitchMapping$0;

        static {
            KotlinClassHeader.Kind.values();
            int[] iArr = new int[6];
            $EnumSwitchMapping$0 = iArr;
            iArr[KotlinClassHeader.Kind.FILE_FACADE.ordinal()] = 1;
            iArr[KotlinClassHeader.Kind.MULTIFILE_CLASS.ordinal()] = 2;
            iArr[KotlinClassHeader.Kind.MULTIFILE_CLASS_PART.ordinal()] = 3;
            iArr[KotlinClassHeader.Kind.SYNTHETIC_CLASS.ordinal()] = 4;
            iArr[KotlinClassHeader.Kind.UNKNOWN.ordinal()] = 5;
            iArr[KotlinClassHeader.Kind.CLASS.ordinal()] = 6;
        }
    }

    public KClassImpl(@NotNull Class<T> jClass) {
        Intrinsics.checkNotNullParameter(jClass, "jClass");
        this.jClass = jClass;
        ReflectProperties.LazyVal<KClassImpl<T>.Data> lazy = ReflectProperties.lazy(new Function0<KClassImpl<T>.Data>() { // from class: kotlin.reflect.jvm.internal.KClassImpl$data$1
            {
                super(0);
            }

            @Override // kotlin.jvm.functions.Function0
            public final KClassImpl<T>.Data invoke() {
                return new KClassImpl.Data();
            }
        });
        Intrinsics.checkNotNullExpressionValue(lazy, "ReflectProperties.lazy { Data() }");
        this.data = lazy;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final ClassId getClassId() {
        return RuntimeTypeMapper.INSTANCE.mapJvmClassToKotlinClassId(getJClass());
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final Void reportUnresolvedClass() {
        KotlinClassHeader classHeader;
        ReflectKotlinClass create = ReflectKotlinClass.Factory.create(getJClass());
        KotlinClassHeader.Kind kind = (create == null || (classHeader = create.getClassHeader()) == null) ? null : classHeader.getKind();
        if (kind != null) {
            int ordinal = kind.ordinal();
            if (ordinal == 0) {
                StringBuilder m586H = C1499a.m586H("Unknown class: ");
                m586H.append(getJClass());
                m586H.append(" (kind = ");
                m586H.append(kind);
                m586H.append(')');
                throw new KotlinReflectionInternalError(m586H.toString());
            }
            if (ordinal != 1) {
                if (ordinal != 2) {
                    if (ordinal == 3) {
                        StringBuilder m590L = C1499a.m590L("This class is an internal synthetic class generated by the Kotlin compiler, such as an anonymous class for a lambda, a SAM wrapper, a callable reference, etc. It's not a Kotlin class or interface, so the reflection ", "library has no idea what declarations does it have. Please use Java reflection to inspect this class: ");
                        m590L.append(getJClass());
                        throw new UnsupportedOperationException(m590L.toString());
                    }
                    if (ordinal != 4 && ordinal != 5) {
                        throw new NoWhenBranchMatchedException();
                    }
                }
                StringBuilder m590L2 = C1499a.m590L("Packages and file facades are not yet supported in Kotlin reflection. ", "Meanwhile please use Java reflection to inspect this class: ");
                m590L2.append(getJClass());
                throw new UnsupportedOperationException(m590L2.toString());
            }
        }
        StringBuilder m586H2 = C1499a.m586H("Unresolved class: ");
        m586H2.append(getJClass());
        throw new KotlinReflectionInternalError(m586H2.toString());
    }

    @Override // kotlin.reflect.KClass
    public boolean equals(@Nullable Object other) {
        return (other instanceof KClassImpl) && Intrinsics.areEqual(JvmClassMappingKt.getJavaObjectType(this), JvmClassMappingKt.getJavaObjectType((KClass) other));
    }

    @Override // kotlin.reflect.KAnnotatedElement
    @NotNull
    public List<Annotation> getAnnotations() {
        return this.data.invoke().getAnnotations();
    }

    @Override // kotlin.reflect.jvm.internal.KDeclarationContainerImpl
    @NotNull
    public Collection<ConstructorDescriptor> getConstructorDescriptors() {
        ClassDescriptor descriptor = getDescriptor();
        if (descriptor.getKind() == ClassKind.INTERFACE || descriptor.getKind() == ClassKind.OBJECT) {
            return CollectionsKt__CollectionsKt.emptyList();
        }
        Collection<ClassConstructorDescriptor> constructors = descriptor.getConstructors();
        Intrinsics.checkNotNullExpressionValue(constructors, "descriptor.constructors");
        return constructors;
    }

    @Override // kotlin.reflect.KClass
    @NotNull
    public Collection<KFunction<T>> getConstructors() {
        return this.data.invoke().getConstructors();
    }

    @NotNull
    public final ReflectProperties.LazyVal<KClassImpl<T>.Data> getData() {
        return this.data;
    }

    @Override // kotlin.reflect.jvm.internal.KDeclarationContainerImpl
    @NotNull
    public Collection<FunctionDescriptor> getFunctions(@NotNull Name name) {
        Intrinsics.checkNotNullParameter(name, "name");
        MemberScope memberScope$kotlin_reflection = getMemberScope$kotlin_reflection();
        NoLookupLocation noLookupLocation = NoLookupLocation.FROM_REFLECTION;
        return CollectionsKt___CollectionsKt.plus((Collection) memberScope$kotlin_reflection.getContributedFunctions(name, noLookupLocation), (Iterable) getStaticScope$kotlin_reflection().getContributedFunctions(name, noLookupLocation));
    }

    @Override // kotlin.jvm.internal.ClassBasedDeclarationContainer
    @NotNull
    public Class<T> getJClass() {
        return this.jClass;
    }

    @Override // kotlin.reflect.jvm.internal.KDeclarationContainerImpl
    @Nullable
    public PropertyDescriptor getLocalProperty(int index) {
        Class<?> declaringClass;
        if (Intrinsics.areEqual(getJClass().getSimpleName(), "DefaultImpls") && (declaringClass = getJClass().getDeclaringClass()) != null && declaringClass.isInterface()) {
            KClass kotlinClass = JvmClassMappingKt.getKotlinClass(declaringClass);
            Objects.requireNonNull(kotlinClass, "null cannot be cast to non-null type kotlin.reflect.jvm.internal.KClassImpl<*>");
            return ((KClassImpl) kotlinClass).getLocalProperty(index);
        }
        ClassDescriptor descriptor = getDescriptor();
        if (!(descriptor instanceof DeserializedClassDescriptor)) {
            descriptor = null;
        }
        DeserializedClassDescriptor deserializedClassDescriptor = (DeserializedClassDescriptor) descriptor;
        if (deserializedClassDescriptor == null) {
            return null;
        }
        ProtoBuf.Class classProto = deserializedClassDescriptor.getClassProto();
        GeneratedMessageLite.GeneratedExtension<ProtoBuf.Class, List<ProtoBuf.Property>> generatedExtension = JvmProtoBuf.classLocalVariable;
        Intrinsics.checkNotNullExpressionValue(generatedExtension, "JvmProtoBuf.classLocalVariable");
        ProtoBuf.Property property = (ProtoBuf.Property) ProtoBufUtilKt.getExtensionOrNull(classProto, generatedExtension, index);
        if (property != null) {
            return (PropertyDescriptor) UtilKt.deserializeToDescriptor(getJClass(), property, deserializedClassDescriptor.getC().getNameResolver(), deserializedClassDescriptor.getC().getTypeTable(), deserializedClassDescriptor.getMetadataVersion(), KClassImpl$getLocalProperty$2$1$1.INSTANCE);
        }
        return null;
    }

    @NotNull
    public final MemberScope getMemberScope$kotlin_reflection() {
        return getDescriptor().getDefaultType().getMemberScope();
    }

    @Override // kotlin.reflect.KDeclarationContainer
    @NotNull
    public Collection<KCallable<?>> getMembers() {
        return this.data.invoke().getAllMembers();
    }

    @Override // kotlin.reflect.KClass
    @NotNull
    public Collection<KClass<?>> getNestedClasses() {
        return this.data.invoke().getNestedClasses();
    }

    @Override // kotlin.reflect.KClass
    @Nullable
    public T getObjectInstance() {
        return this.data.invoke().getObjectInstance();
    }

    @Override // kotlin.reflect.jvm.internal.KDeclarationContainerImpl
    @NotNull
    public Collection<PropertyDescriptor> getProperties(@NotNull Name name) {
        Intrinsics.checkNotNullParameter(name, "name");
        MemberScope memberScope$kotlin_reflection = getMemberScope$kotlin_reflection();
        NoLookupLocation noLookupLocation = NoLookupLocation.FROM_REFLECTION;
        return CollectionsKt___CollectionsKt.plus((Collection) memberScope$kotlin_reflection.getContributedVariables(name, noLookupLocation), (Iterable) getStaticScope$kotlin_reflection().getContributedVariables(name, noLookupLocation));
    }

    @Override // kotlin.reflect.KClass
    @Nullable
    public String getQualifiedName() {
        return this.data.invoke().getQualifiedName();
    }

    @Override // kotlin.reflect.KClass
    @NotNull
    public List<KClass<? extends T>> getSealedSubclasses() {
        return this.data.invoke().getSealedSubclasses();
    }

    @Override // kotlin.reflect.KClass
    @Nullable
    public String getSimpleName() {
        return this.data.invoke().getSimpleName();
    }

    @NotNull
    public final MemberScope getStaticScope$kotlin_reflection() {
        MemberScope staticScope = getDescriptor().getStaticScope();
        Intrinsics.checkNotNullExpressionValue(staticScope, "descriptor.staticScope");
        return staticScope;
    }

    @Override // kotlin.reflect.KClass
    @NotNull
    public List<KType> getSupertypes() {
        return this.data.invoke().getSupertypes();
    }

    @Override // kotlin.reflect.KClass
    @NotNull
    public List<KTypeParameter> getTypeParameters() {
        return this.data.invoke().getTypeParameters();
    }

    @Override // kotlin.reflect.KClass
    @Nullable
    public KVisibility getVisibility() {
        DescriptorVisibility visibility = getDescriptor().getVisibility();
        Intrinsics.checkNotNullExpressionValue(visibility, "descriptor.visibility");
        return UtilKt.toKVisibility(visibility);
    }

    @Override // kotlin.reflect.KClass
    public int hashCode() {
        return JvmClassMappingKt.getJavaObjectType(this).hashCode();
    }

    @Override // kotlin.reflect.KClass
    public boolean isAbstract() {
        return getDescriptor().getModality() == Modality.ABSTRACT;
    }

    @Override // kotlin.reflect.KClass
    public boolean isCompanion() {
        return getDescriptor().isCompanionObject();
    }

    @Override // kotlin.reflect.KClass
    public boolean isData() {
        return getDescriptor().isData();
    }

    @Override // kotlin.reflect.KClass
    public boolean isFinal() {
        return getDescriptor().getModality() == Modality.FINAL;
    }

    @Override // kotlin.reflect.KClass
    public boolean isFun() {
        return getDescriptor().isFun();
    }

    @Override // kotlin.reflect.KClass
    public boolean isInner() {
        return getDescriptor().isInner();
    }

    @Override // kotlin.reflect.KClass
    public boolean isInstance(@Nullable Object value) {
        Integer functionClassArity = ReflectClassUtilKt.getFunctionClassArity(getJClass());
        if (functionClassArity != null) {
            return TypeIntrinsics.isFunctionOfArity(value, functionClassArity.intValue());
        }
        Class wrapperByPrimitive = ReflectClassUtilKt.getWrapperByPrimitive(getJClass());
        if (wrapperByPrimitive == null) {
            wrapperByPrimitive = getJClass();
        }
        return wrapperByPrimitive.isInstance(value);
    }

    @Override // kotlin.reflect.KClass
    public boolean isOpen() {
        return getDescriptor().getModality() == Modality.OPEN;
    }

    @Override // kotlin.reflect.KClass
    public boolean isSealed() {
        return getDescriptor().getModality() == Modality.SEALED;
    }

    @Override // kotlin.reflect.KClass
    public boolean isValue() {
        return getDescriptor().isValue();
    }

    @NotNull
    public String toString() {
        String str;
        StringBuilder m586H = C1499a.m586H("class ");
        ClassId classId = getClassId();
        FqName packageFqName = classId.getPackageFqName();
        Intrinsics.checkNotNullExpressionValue(packageFqName, "classId.packageFqName");
        if (packageFqName.isRoot()) {
            str = "";
        } else {
            str = packageFqName.asString() + ".";
        }
        String asString = classId.getRelativeClassName().asString();
        Intrinsics.checkNotNullExpressionValue(asString, "classId.relativeClassName.asString()");
        m586H.append(str + StringsKt__StringsJVMKt.replace$default(asString, '.', Typography.dollar, false, 4, (Object) null));
        return m586H.toString();
    }

    @Override // kotlin.reflect.jvm.internal.KClassifierImpl
    @NotNull
    public ClassDescriptor getDescriptor() {
        return this.data.invoke().getDescriptor();
    }
}
