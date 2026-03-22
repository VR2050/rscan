package kotlin.reflect.jvm.internal;

import androidx.exifinterface.media.ExifInterface;
import java.lang.reflect.Field;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.CallableReference;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.PropertyReference1Impl;
import kotlin.jvm.internal.Reflection;
import kotlin.reflect.KFunction;
import kotlin.reflect.KMutableProperty;
import kotlin.reflect.KProperty;
import kotlin.reflect.jvm.internal.JvmPropertySignature;
import kotlin.reflect.jvm.internal.KPropertyImpl;
import kotlin.reflect.jvm.internal.ReflectProperties;
import kotlin.reflect.jvm.internal.calls.Caller;
import kotlin.reflect.jvm.internal.calls.InlineClassAwareCallerKt;
import kotlin.reflect.jvm.internal.impl.descriptors.ClassDescriptor;
import kotlin.reflect.jvm.internal.impl.descriptors.DeclarationDescriptor;
import kotlin.reflect.jvm.internal.impl.descriptors.PropertyAccessorDescriptor;
import kotlin.reflect.jvm.internal.impl.descriptors.PropertyDescriptor;
import kotlin.reflect.jvm.internal.impl.descriptors.PropertyGetterDescriptor;
import kotlin.reflect.jvm.internal.impl.descriptors.PropertySetterDescriptor;
import kotlin.reflect.jvm.internal.impl.descriptors.annotations.Annotations;
import kotlin.reflect.jvm.internal.impl.load.java.DescriptorsJvmAbiUtil;
import kotlin.reflect.jvm.internal.impl.metadata.jvm.deserialization.JvmMemberSignature;
import kotlin.reflect.jvm.internal.impl.metadata.jvm.deserialization.JvmProtoBufUtil;
import kotlin.reflect.jvm.internal.impl.resolve.DescriptorFactory;
import kotlin.text.Typography;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000b\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\u0000\n\u0002\b\u0004\n\u0002\u0010\u000b\n\u0002\b\u0002\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0002\b\b\n\u0002\u0018\u0002\n\u0002\b\u0007\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\t\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0013\b \u0018\u0000 F*\u0006\b\u0000\u0010\u0001 \u00012\b\u0012\u0004\u0012\u00028\u00000\u00022\b\u0012\u0004\u0012\u00028\u00000\u0003:\u0004GFHIB\u0019\b\u0016\u0012\u0006\u0010)\u001a\u00020(\u0012\u0006\u0010@\u001a\u000203¢\u0006\u0004\bA\u0010BB5\b\u0002\u0012\u0006\u0010)\u001a\u00020(\u0012\u0006\u0010\u0018\u001a\u00020\u0013\u0012\u0006\u0010\"\u001a\u00020\u0013\u0012\b\u0010C\u001a\u0004\u0018\u000103\u0012\b\u00100\u001a\u0004\u0018\u00010\b¢\u0006\u0004\bA\u0010DB+\b\u0016\u0012\u0006\u0010)\u001a\u00020(\u0012\u0006\u0010\u0018\u001a\u00020\u0013\u0012\u0006\u0010\"\u001a\u00020\u0013\u0012\b\u0010/\u001a\u0004\u0018\u00010\b¢\u0006\u0004\bA\u0010EJ\u0011\u0010\u0005\u001a\u0004\u0018\u00010\u0004H\u0004¢\u0006\u0004\b\u0005\u0010\u0006J%\u0010\n\u001a\u0004\u0018\u00010\b2\b\u0010\u0007\u001a\u0004\u0018\u00010\u00042\b\u0010\t\u001a\u0004\u0018\u00010\bH\u0004¢\u0006\u0004\b\n\u0010\u000bJ\u001a\u0010\u000e\u001a\u00020\r2\b\u0010\f\u001a\u0004\u0018\u00010\bH\u0096\u0002¢\u0006\u0004\b\u000e\u0010\u000fJ\u000f\u0010\u0011\u001a\u00020\u0010H\u0016¢\u0006\u0004\b\u0011\u0010\u0012J\u000f\u0010\u0014\u001a\u00020\u0013H\u0016¢\u0006\u0004\b\u0014\u0010\u0015R\u0016\u0010\u0016\u001a\u00020\r8V@\u0016X\u0096\u0004¢\u0006\u0006\u001a\u0004\b\u0016\u0010\u0017R\u001c\u0010\u0018\u001a\u00020\u00138\u0016@\u0016X\u0096\u0004¢\u0006\f\n\u0004\b\u0018\u0010\u0019\u001a\u0004\b\u001a\u0010\u0015R\u0016\u0010\u001b\u001a\u00020\r8V@\u0016X\u0096\u0004¢\u0006\u0006\u001a\u0004\b\u001b\u0010\u0017R\u001c\u0010\u001f\u001a\b\u0012\u0004\u0012\u00028\u00000\u001c8&@&X¦\u0004¢\u0006\u0006\u001a\u0004\b\u001d\u0010\u001eR\u0015\u0010!\u001a\u0004\u0018\u00010\u00048F@\u0006¢\u0006\u0006\u001a\u0004\b \u0010\u0006R\u0019\u0010\"\u001a\u00020\u00138\u0006@\u0006¢\u0006\f\n\u0004\b\"\u0010\u0019\u001a\u0004\b#\u0010\u0015R\u001e\u0010%\u001a\n\u0012\u0006\u0012\u0004\u0018\u00010\u00040$8\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\b%\u0010&R\u0016\u0010'\u001a\u00020\r8V@\u0016X\u0096\u0004¢\u0006\u0006\u001a\u0004\b'\u0010\u0017R\u001c\u0010)\u001a\u00020(8\u0016@\u0016X\u0096\u0004¢\u0006\f\n\u0004\b)\u0010*\u001a\u0004\b+\u0010,R\u0015\u0010/\u001a\u0004\u0018\u00010\b8F@\u0006¢\u0006\u0006\u001a\u0004\b-\u0010.R\u0018\u00100\u001a\u0004\u0018\u00010\b8\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\b0\u00101R$\u00105\u001a\u0010\u0012\f\u0012\n 4*\u0004\u0018\u00010303028\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\b5\u00106R\u001a\u0010:\u001a\u0006\u0012\u0002\b\u0003078V@\u0016X\u0096\u0004¢\u0006\u0006\u001a\u0004\b8\u00109R\u0016\u0010;\u001a\u00020\r8V@\u0016X\u0096\u0004¢\u0006\u0006\u001a\u0004\b;\u0010\u0017R\u001c\u0010=\u001a\b\u0012\u0002\b\u0003\u0018\u0001078V@\u0016X\u0096\u0004¢\u0006\u0006\u001a\u0004\b<\u00109R\u0016\u0010@\u001a\u0002038V@\u0016X\u0096\u0004¢\u0006\u0006\u001a\u0004\b>\u0010?¨\u0006J"}, m5311d2 = {"Lkotlin/reflect/jvm/internal/KPropertyImpl;", ExifInterface.GPS_MEASUREMENT_INTERRUPTED, "Lkotlin/reflect/jvm/internal/KCallableImpl;", "Lkotlin/reflect/KProperty;", "Ljava/lang/reflect/Field;", "computeDelegateField", "()Ljava/lang/reflect/Field;", "field", "", "receiver", "getDelegate", "(Ljava/lang/reflect/Field;Ljava/lang/Object;)Ljava/lang/Object;", "other", "", "equals", "(Ljava/lang/Object;)Z", "", "hashCode", "()I", "", "toString", "()Ljava/lang/String;", "isConst", "()Z", "name", "Ljava/lang/String;", "getName", "isLateinit", "Lkotlin/reflect/jvm/internal/KPropertyImpl$Getter;", "getGetter", "()Lkotlin/reflect/jvm/internal/KPropertyImpl$Getter;", "getter", "getJavaField", "javaField", "signature", "getSignature", "Lkotlin/reflect/jvm/internal/ReflectProperties$LazyVal;", "_javaField", "Lkotlin/reflect/jvm/internal/ReflectProperties$LazyVal;", "isSuspend", "Lkotlin/reflect/jvm/internal/KDeclarationContainerImpl;", "container", "Lkotlin/reflect/jvm/internal/KDeclarationContainerImpl;", "getContainer", "()Lkotlin/reflect/jvm/internal/KDeclarationContainerImpl;", "getBoundReceiver", "()Ljava/lang/Object;", "boundReceiver", "rawBoundReceiver", "Ljava/lang/Object;", "Lkotlin/reflect/jvm/internal/ReflectProperties$LazySoftVal;", "Lkotlin/reflect/jvm/internal/impl/descriptors/PropertyDescriptor;", "kotlin.jvm.PlatformType", "_descriptor", "Lkotlin/reflect/jvm/internal/ReflectProperties$LazySoftVal;", "Lkotlin/reflect/jvm/internal/calls/Caller;", "getCaller", "()Lkotlin/reflect/jvm/internal/calls/Caller;", "caller", "isBound", "getDefaultCaller", "defaultCaller", "getDescriptor", "()Lorg/jetbrains/kotlin/descriptors/PropertyDescriptor;", "descriptor", "<init>", "(Lkotlin/reflect/jvm/internal/KDeclarationContainerImpl;Lorg/jetbrains/kotlin/descriptors/PropertyDescriptor;)V", "descriptorInitialValue", "(Lkotlin/reflect/jvm/internal/KDeclarationContainerImpl;Ljava/lang/String;Ljava/lang/String;Lorg/jetbrains/kotlin/descriptors/PropertyDescriptor;Ljava/lang/Object;)V", "(Lkotlin/reflect/jvm/internal/KDeclarationContainerImpl;Ljava/lang/String;Ljava/lang/String;Ljava/lang/Object;)V", "Companion", "Accessor", "Getter", "Setter", "kotlin-reflection"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes.dex */
public abstract class KPropertyImpl<V> extends KCallableImpl<V> implements KProperty<V> {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    @NotNull
    private static final Object EXTENSION_PROPERTY_DELEGATE = new Object();
    private final ReflectProperties.LazySoftVal<PropertyDescriptor> _descriptor;
    private final ReflectProperties.LazyVal<Field> _javaField;

    @NotNull
    private final KDeclarationContainerImpl container;

    @NotNull
    private final String name;
    private final Object rawBoundReceiver;

    @NotNull
    private final String signature;

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000<\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u000b\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0006\b&\u0018\u0000*\u0006\b\u0001\u0010\u0001 \u0001*\u0006\b\u0002\u0010\u0002 \u00012\b\u0012\u0004\u0012\u00028\u00020\u00032\b\u0012\u0004\u0012\u00028\u00010\u00042\b\u0012\u0004\u0012\u00028\u00020\u0005B\u0007¢\u0006\u0004\b\u001e\u0010\u001fR\u0016\u0010\u0007\u001a\u00020\u00068V@\u0016X\u0096\u0004¢\u0006\u0006\u001a\u0004\b\u0007\u0010\bR\u0016\u0010\t\u001a\u00020\u00068V@\u0016X\u0096\u0004¢\u0006\u0006\u001a\u0004\b\t\u0010\bR\u0016\u0010\n\u001a\u00020\u00068V@\u0016X\u0096\u0004¢\u0006\u0006\u001a\u0004\b\n\u0010\bR\u0016\u0010\u000b\u001a\u00020\u00068V@\u0016X\u0096\u0004¢\u0006\u0006\u001a\u0004\b\u000b\u0010\bR\u0016\u0010\f\u001a\u00020\u00068V@\u0016X\u0096\u0004¢\u0006\u0006\u001a\u0004\b\f\u0010\bR\u001c\u0010\u0010\u001a\b\u0012\u0004\u0012\u00028\u00010\r8&@&X¦\u0004¢\u0006\u0006\u001a\u0004\b\u000e\u0010\u000fR\u0016\u0010\u0014\u001a\u00020\u00118V@\u0016X\u0096\u0004¢\u0006\u0006\u001a\u0004\b\u0012\u0010\u0013R\u001c\u0010\u0018\u001a\b\u0012\u0002\b\u0003\u0018\u00010\u00158V@\u0016X\u0096\u0004¢\u0006\u0006\u001a\u0004\b\u0016\u0010\u0017R\u0016\u0010\u0019\u001a\u00020\u00068V@\u0016X\u0096\u0004¢\u0006\u0006\u001a\u0004\b\u0019\u0010\bR\u0016\u0010\u001d\u001a\u00020\u001a8&@&X¦\u0004¢\u0006\u0006\u001a\u0004\b\u001b\u0010\u001c¨\u0006 "}, m5311d2 = {"Lkotlin/reflect/jvm/internal/KPropertyImpl$Accessor;", "PropertyType", "ReturnType", "Lkotlin/reflect/jvm/internal/KCallableImpl;", "Lkotlin/reflect/KProperty$Accessor;", "Lkotlin/reflect/KFunction;", "", "isSuspend", "()Z", "isBound", "isInline", "isOperator", "isInfix", "Lkotlin/reflect/jvm/internal/KPropertyImpl;", "getProperty", "()Lkotlin/reflect/jvm/internal/KPropertyImpl;", "property", "Lkotlin/reflect/jvm/internal/KDeclarationContainerImpl;", "getContainer", "()Lkotlin/reflect/jvm/internal/KDeclarationContainerImpl;", "container", "Lkotlin/reflect/jvm/internal/calls/Caller;", "getDefaultCaller", "()Lkotlin/reflect/jvm/internal/calls/Caller;", "defaultCaller", "isExternal", "Lkotlin/reflect/jvm/internal/impl/descriptors/PropertyAccessorDescriptor;", "getDescriptor", "()Lorg/jetbrains/kotlin/descriptors/PropertyAccessorDescriptor;", "descriptor", "<init>", "()V", "kotlin-reflection"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static abstract class Accessor<PropertyType, ReturnType> extends KCallableImpl<ReturnType> implements KFunction<ReturnType>, KProperty.Accessor<PropertyType> {
        @Override // kotlin.reflect.jvm.internal.KCallableImpl
        @NotNull
        public KDeclarationContainerImpl getContainer() {
            return getProperty().getContainer();
        }

        @Override // kotlin.reflect.jvm.internal.KCallableImpl
        @Nullable
        public Caller<?> getDefaultCaller() {
            return null;
        }

        @Override // kotlin.reflect.jvm.internal.KCallableImpl
        @NotNull
        public abstract PropertyAccessorDescriptor getDescriptor();

        @NotNull
        public abstract KPropertyImpl<PropertyType> getProperty();

        @Override // kotlin.reflect.jvm.internal.KCallableImpl
        public boolean isBound() {
            return getProperty().isBound();
        }

        @Override // kotlin.reflect.KFunction
        public boolean isExternal() {
            return getDescriptor().isExternal();
        }

        @Override // kotlin.reflect.KFunction
        public boolean isInfix() {
            return getDescriptor().isInfix();
        }

        @Override // kotlin.reflect.KFunction
        public boolean isInline() {
            return getDescriptor().isInline();
        }

        @Override // kotlin.reflect.KFunction
        public boolean isOperator() {
            return getDescriptor().isOperator();
        }

        @Override // kotlin.reflect.KCallable
        public boolean isSuspend() {
            return getDescriptor().isSuspend();
        }
    }

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\f\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0007\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0006\u0010\u0007R\u0019\u0010\u0002\u001a\u00020\u00018\u0006@\u0006¢\u0006\f\n\u0004\b\u0002\u0010\u0003\u001a\u0004\b\u0004\u0010\u0005¨\u0006\b"}, m5311d2 = {"Lkotlin/reflect/jvm/internal/KPropertyImpl$Companion;", "", "EXTENSION_PROPERTY_DELEGATE", "Ljava/lang/Object;", "getEXTENSION_PROPERTY_DELEGATE", "()Ljava/lang/Object;", "<init>", "()V", "kotlin-reflection"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        @NotNull
        public final Object getEXTENSION_PROPERTY_DELEGATE() {
            return KPropertyImpl.EXTENSION_PROPERTY_DELEGATE;
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }
    }

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000<\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u000e\n\u0002\b\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u000b\n\u0002\b\u0002\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0007\n\u0002\u0018\u0002\n\u0002\b\b\b&\u0018\u0000*\u0006\b\u0001\u0010\u0001 \u00012\u000e\u0012\u0004\u0012\u00028\u0001\u0012\u0004\u0012\u00028\u00010\u00022\b\u0012\u0004\u0012\u00028\u00010\u0003B\u0007¢\u0006\u0004\b\u001d\u0010\u001eJ\u000f\u0010\u0005\u001a\u00020\u0004H\u0016¢\u0006\u0004\b\u0005\u0010\u0006J\u001a\u0010\n\u001a\u00020\t2\b\u0010\b\u001a\u0004\u0018\u00010\u0007H\u0096\u0002¢\u0006\u0004\b\n\u0010\u000bJ\u000f\u0010\r\u001a\u00020\fH\u0016¢\u0006\u0004\b\r\u0010\u000eR\u001d\u0010\u0014\u001a\u00020\u000f8V@\u0016X\u0096\u0084\u0002¢\u0006\f\n\u0004\b\u0010\u0010\u0011\u001a\u0004\b\u0012\u0010\u0013R\u0016\u0010\u0016\u001a\u00020\u00048V@\u0016X\u0096\u0004¢\u0006\u0006\u001a\u0004\b\u0015\u0010\u0006R!\u0010\u001c\u001a\u0006\u0012\u0002\b\u00030\u00178V@\u0016X\u0096\u0084\u0002¢\u0006\f\n\u0004\b\u0018\u0010\u0019\u001a\u0004\b\u001a\u0010\u001b¨\u0006\u001f"}, m5311d2 = {"Lkotlin/reflect/jvm/internal/KPropertyImpl$Getter;", ExifInterface.GPS_MEASUREMENT_INTERRUPTED, "Lkotlin/reflect/jvm/internal/KPropertyImpl$Accessor;", "Lkotlin/reflect/KProperty$Getter;", "", "toString", "()Ljava/lang/String;", "", "other", "", "equals", "(Ljava/lang/Object;)Z", "", "hashCode", "()I", "Lkotlin/reflect/jvm/internal/impl/descriptors/PropertyGetterDescriptor;", "descriptor$delegate", "Lkotlin/reflect/jvm/internal/ReflectProperties$LazySoftVal;", "getDescriptor", "()Lorg/jetbrains/kotlin/descriptors/PropertyGetterDescriptor;", "descriptor", "getName", "name", "Lkotlin/reflect/jvm/internal/calls/Caller;", "caller$delegate", "Lkotlin/reflect/jvm/internal/ReflectProperties$LazyVal;", "getCaller", "()Lkotlin/reflect/jvm/internal/calls/Caller;", "caller", "<init>", "()V", "kotlin-reflection"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static abstract class Getter<V> extends Accessor<V, V> implements KProperty.Getter<V> {
        public static final /* synthetic */ KProperty[] $$delegatedProperties = {Reflection.property1(new PropertyReference1Impl(Reflection.getOrCreateKotlinClass(Getter.class), "descriptor", "getDescriptor()Lorg/jetbrains/kotlin/descriptors/PropertyGetterDescriptor;")), Reflection.property1(new PropertyReference1Impl(Reflection.getOrCreateKotlinClass(Getter.class), "caller", "getCaller()Lkotlin/reflect/jvm/internal/calls/Caller;"))};

        /* renamed from: descriptor$delegate, reason: from kotlin metadata */
        @NotNull
        private final ReflectProperties.LazySoftVal descriptor = ReflectProperties.lazySoft(new Function0<PropertyGetterDescriptor>() { // from class: kotlin.reflect.jvm.internal.KPropertyImpl$Getter$descriptor$2
            {
                super(0);
            }

            @Override // kotlin.jvm.functions.Function0
            public final PropertyGetterDescriptor invoke() {
                PropertyGetterDescriptor getter = KPropertyImpl.Getter.this.getProperty().getDescriptor().getGetter();
                return getter != null ? getter : DescriptorFactory.createDefaultGetter(KPropertyImpl.Getter.this.getProperty().getDescriptor(), Annotations.Companion.getEMPTY());
            }
        });

        /* renamed from: caller$delegate, reason: from kotlin metadata */
        @NotNull
        private final ReflectProperties.LazyVal caller = ReflectProperties.lazy(new Function0<Caller<?>>() { // from class: kotlin.reflect.jvm.internal.KPropertyImpl$Getter$caller$2
            {
                super(0);
            }

            @Override // kotlin.jvm.functions.Function0
            public final Caller<?> invoke() {
                Caller<?> computeCallerForAccessor;
                computeCallerForAccessor = KPropertyImplKt.computeCallerForAccessor(KPropertyImpl.Getter.this, true);
                return computeCallerForAccessor;
            }
        });

        public boolean equals(@Nullable Object other) {
            return (other instanceof Getter) && Intrinsics.areEqual(getProperty(), ((Getter) other).getProperty());
        }

        @Override // kotlin.reflect.jvm.internal.KCallableImpl
        @NotNull
        public Caller<?> getCaller() {
            return (Caller) this.caller.getValue(this, $$delegatedProperties[1]);
        }

        @Override // kotlin.reflect.jvm.internal.KPropertyImpl.Accessor, kotlin.reflect.jvm.internal.KCallableImpl
        @NotNull
        public PropertyGetterDescriptor getDescriptor() {
            return (PropertyGetterDescriptor) this.descriptor.getValue(this, $$delegatedProperties[0]);
        }

        @Override // kotlin.reflect.KCallable
        @NotNull
        public String getName() {
            StringBuilder m586H = C1499a.m586H("<get-");
            m586H.append(getProperty().getName());
            m586H.append(Typography.greater);
            return m586H.toString();
        }

        public int hashCode() {
            return getProperty().hashCode();
        }

        @NotNull
        public String toString() {
            StringBuilder m586H = C1499a.m586H("getter of ");
            m586H.append(getProperty());
            return m586H.toString();
        }
    }

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000@\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u000e\n\u0002\b\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u000b\n\u0002\b\u0002\n\u0002\u0010\b\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\b\b&\u0018\u0000*\u0004\b\u0001\u0010\u00012\u000e\u0012\u0004\u0012\u00028\u0001\u0012\u0004\u0012\u00020\u00030\u00022\b\u0012\u0004\u0012\u00028\u00010\u0004B\u0007¢\u0006\u0004\b\u001e\u0010\u001fJ\u000f\u0010\u0006\u001a\u00020\u0005H\u0016¢\u0006\u0004\b\u0006\u0010\u0007J\u001a\u0010\u000b\u001a\u00020\n2\b\u0010\t\u001a\u0004\u0018\u00010\bH\u0096\u0002¢\u0006\u0004\b\u000b\u0010\fJ\u000f\u0010\u000e\u001a\u00020\rH\u0016¢\u0006\u0004\b\u000e\u0010\u000fR\u0016\u0010\u0011\u001a\u00020\u00058V@\u0016X\u0096\u0004¢\u0006\u0006\u001a\u0004\b\u0010\u0010\u0007R!\u0010\u0017\u001a\u0006\u0012\u0002\b\u00030\u00128V@\u0016X\u0096\u0084\u0002¢\u0006\f\n\u0004\b\u0013\u0010\u0014\u001a\u0004\b\u0015\u0010\u0016R\u001d\u0010\u001d\u001a\u00020\u00188V@\u0016X\u0096\u0084\u0002¢\u0006\f\n\u0004\b\u0019\u0010\u001a\u001a\u0004\b\u001b\u0010\u001c¨\u0006 "}, m5311d2 = {"Lkotlin/reflect/jvm/internal/KPropertyImpl$Setter;", ExifInterface.GPS_MEASUREMENT_INTERRUPTED, "Lkotlin/reflect/jvm/internal/KPropertyImpl$Accessor;", "", "Lkotlin/reflect/KMutableProperty$Setter;", "", "toString", "()Ljava/lang/String;", "", "other", "", "equals", "(Ljava/lang/Object;)Z", "", "hashCode", "()I", "getName", "name", "Lkotlin/reflect/jvm/internal/calls/Caller;", "caller$delegate", "Lkotlin/reflect/jvm/internal/ReflectProperties$LazyVal;", "getCaller", "()Lkotlin/reflect/jvm/internal/calls/Caller;", "caller", "Lkotlin/reflect/jvm/internal/impl/descriptors/PropertySetterDescriptor;", "descriptor$delegate", "Lkotlin/reflect/jvm/internal/ReflectProperties$LazySoftVal;", "getDescriptor", "()Lorg/jetbrains/kotlin/descriptors/PropertySetterDescriptor;", "descriptor", "<init>", "()V", "kotlin-reflection"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static abstract class Setter<V> extends Accessor<V, Unit> implements KMutableProperty.Setter<V> {
        public static final /* synthetic */ KProperty[] $$delegatedProperties = {Reflection.property1(new PropertyReference1Impl(Reflection.getOrCreateKotlinClass(Setter.class), "descriptor", "getDescriptor()Lorg/jetbrains/kotlin/descriptors/PropertySetterDescriptor;")), Reflection.property1(new PropertyReference1Impl(Reflection.getOrCreateKotlinClass(Setter.class), "caller", "getCaller()Lkotlin/reflect/jvm/internal/calls/Caller;"))};

        /* renamed from: descriptor$delegate, reason: from kotlin metadata */
        @NotNull
        private final ReflectProperties.LazySoftVal descriptor = ReflectProperties.lazySoft(new Function0<PropertySetterDescriptor>() { // from class: kotlin.reflect.jvm.internal.KPropertyImpl$Setter$descriptor$2
            {
                super(0);
            }

            @Override // kotlin.jvm.functions.Function0
            public final PropertySetterDescriptor invoke() {
                PropertySetterDescriptor setter = KPropertyImpl.Setter.this.getProperty().getDescriptor().getSetter();
                if (setter != null) {
                    return setter;
                }
                PropertyDescriptor descriptor = KPropertyImpl.Setter.this.getProperty().getDescriptor();
                Annotations.Companion companion = Annotations.Companion;
                return DescriptorFactory.createDefaultSetter(descriptor, companion.getEMPTY(), companion.getEMPTY());
            }
        });

        /* renamed from: caller$delegate, reason: from kotlin metadata */
        @NotNull
        private final ReflectProperties.LazyVal caller = ReflectProperties.lazy(new Function0<Caller<?>>() { // from class: kotlin.reflect.jvm.internal.KPropertyImpl$Setter$caller$2
            {
                super(0);
            }

            @Override // kotlin.jvm.functions.Function0
            public final Caller<?> invoke() {
                Caller<?> computeCallerForAccessor;
                computeCallerForAccessor = KPropertyImplKt.computeCallerForAccessor(KPropertyImpl.Setter.this, false);
                return computeCallerForAccessor;
            }
        });

        public boolean equals(@Nullable Object other) {
            return (other instanceof Setter) && Intrinsics.areEqual(getProperty(), ((Setter) other).getProperty());
        }

        @Override // kotlin.reflect.jvm.internal.KCallableImpl
        @NotNull
        public Caller<?> getCaller() {
            return (Caller) this.caller.getValue(this, $$delegatedProperties[1]);
        }

        @Override // kotlin.reflect.jvm.internal.KPropertyImpl.Accessor, kotlin.reflect.jvm.internal.KCallableImpl
        @NotNull
        public PropertySetterDescriptor getDescriptor() {
            return (PropertySetterDescriptor) this.descriptor.getValue(this, $$delegatedProperties[0]);
        }

        @Override // kotlin.reflect.KCallable
        @NotNull
        public String getName() {
            StringBuilder m586H = C1499a.m586H("<set-");
            m586H.append(getProperty().getName());
            m586H.append(Typography.greater);
            return m586H.toString();
        }

        public int hashCode() {
            return getProperty().hashCode();
        }

        @NotNull
        public String toString() {
            StringBuilder m586H = C1499a.m586H("setter of ");
            m586H.append(getProperty());
            return m586H.toString();
        }
    }

    private KPropertyImpl(KDeclarationContainerImpl kDeclarationContainerImpl, String str, String str2, PropertyDescriptor propertyDescriptor, Object obj) {
        this.container = kDeclarationContainerImpl;
        this.name = str;
        this.signature = str2;
        this.rawBoundReceiver = obj;
        ReflectProperties.LazyVal<Field> lazy = ReflectProperties.lazy(new Function0<Field>() { // from class: kotlin.reflect.jvm.internal.KPropertyImpl$_javaField$1
            {
                super(0);
            }

            @Override // kotlin.jvm.functions.Function0
            @Nullable
            public final Field invoke() {
                Class<?> enclosingClass;
                JvmPropertySignature mapPropertySignature = RuntimeTypeMapper.INSTANCE.mapPropertySignature(KPropertyImpl.this.getDescriptor());
                if (!(mapPropertySignature instanceof JvmPropertySignature.KotlinProperty)) {
                    if (mapPropertySignature instanceof JvmPropertySignature.JavaField) {
                        return ((JvmPropertySignature.JavaField) mapPropertySignature).getField();
                    }
                    if ((mapPropertySignature instanceof JvmPropertySignature.JavaMethodProperty) || (mapPropertySignature instanceof JvmPropertySignature.MappedKotlinProperty)) {
                        return null;
                    }
                    throw new NoWhenBranchMatchedException();
                }
                JvmPropertySignature.KotlinProperty kotlinProperty = (JvmPropertySignature.KotlinProperty) mapPropertySignature;
                PropertyDescriptor descriptor = kotlinProperty.getDescriptor();
                JvmMemberSignature.Field jvmFieldSignature$default = JvmProtoBufUtil.getJvmFieldSignature$default(JvmProtoBufUtil.INSTANCE, kotlinProperty.getProto(), kotlinProperty.getNameResolver(), kotlinProperty.getTypeTable(), false, 8, null);
                if (jvmFieldSignature$default == null) {
                    return null;
                }
                if (DescriptorsJvmAbiUtil.isPropertyWithBackingFieldInOuterClass(descriptor) || JvmProtoBufUtil.isMovedFromInterfaceCompanion(kotlinProperty.getProto())) {
                    enclosingClass = KPropertyImpl.this.getContainer().getJClass().getEnclosingClass();
                } else {
                    DeclarationDescriptor containingDeclaration = descriptor.getContainingDeclaration();
                    enclosingClass = containingDeclaration instanceof ClassDescriptor ? UtilKt.toJavaClass((ClassDescriptor) containingDeclaration) : KPropertyImpl.this.getContainer().getJClass();
                }
                if (enclosingClass == null) {
                    return null;
                }
                try {
                    return enclosingClass.getDeclaredField(jvmFieldSignature$default.getName());
                } catch (NoSuchFieldException unused) {
                    return null;
                }
            }
        });
        Intrinsics.checkNotNullExpressionValue(lazy, "ReflectProperties.lazy {…y -> null\n        }\n    }");
        this._javaField = lazy;
        ReflectProperties.LazySoftVal<PropertyDescriptor> lazySoft = ReflectProperties.lazySoft(propertyDescriptor, new Function0<PropertyDescriptor>() { // from class: kotlin.reflect.jvm.internal.KPropertyImpl$_descriptor$1
            {
                super(0);
            }

            @Override // kotlin.jvm.functions.Function0
            public final PropertyDescriptor invoke() {
                return KPropertyImpl.this.getContainer().findPropertyDescriptor(KPropertyImpl.this.getName(), KPropertyImpl.this.getSignature());
            }
        });
        Intrinsics.checkNotNullExpressionValue(lazySoft, "ReflectProperties.lazySo…or(name, signature)\n    }");
        this._descriptor = lazySoft;
    }

    @Nullable
    public final Field computeDelegateField() {
        if (getDescriptor().isDelegated()) {
            return getJavaField();
        }
        return null;
    }

    public boolean equals(@Nullable Object other) {
        KPropertyImpl<?> asKPropertyImpl = UtilKt.asKPropertyImpl(other);
        return asKPropertyImpl != null && Intrinsics.areEqual(getContainer(), asKPropertyImpl.getContainer()) && Intrinsics.areEqual(getName(), asKPropertyImpl.getName()) && Intrinsics.areEqual(this.signature, asKPropertyImpl.signature) && Intrinsics.areEqual(this.rawBoundReceiver, asKPropertyImpl.rawBoundReceiver);
    }

    @Nullable
    public final Object getBoundReceiver() {
        return InlineClassAwareCallerKt.coerceToExpectedReceiverType(this.rawBoundReceiver, getDescriptor());
    }

    @Override // kotlin.reflect.jvm.internal.KCallableImpl
    @NotNull
    public Caller<?> getCaller() {
        return getGetter().getCaller();
    }

    @Override // kotlin.reflect.jvm.internal.KCallableImpl
    @NotNull
    public KDeclarationContainerImpl getContainer() {
        return this.container;
    }

    @Override // kotlin.reflect.jvm.internal.KCallableImpl
    @Nullable
    public Caller<?> getDefaultCaller() {
        return getGetter().getDefaultCaller();
    }

    /* JADX WARN: Code restructure failed: missing block: B:12:?, code lost:
    
        return r2.get(r3);
     */
    @org.jetbrains.annotations.Nullable
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object getDelegate(@org.jetbrains.annotations.Nullable java.lang.reflect.Field r2, @org.jetbrains.annotations.Nullable java.lang.Object r3) {
        /*
            r1 = this;
            java.lang.Object r0 = kotlin.reflect.jvm.internal.KPropertyImpl.EXTENSION_PROPERTY_DELEGATE     // Catch: java.lang.IllegalAccessException -> L39
            if (r3 != r0) goto L30
            kotlin.reflect.jvm.internal.impl.descriptors.PropertyDescriptor r0 = r1.getDescriptor()     // Catch: java.lang.IllegalAccessException -> L39
            kotlin.reflect.jvm.internal.impl.descriptors.ReceiverParameterDescriptor r0 = r0.getExtensionReceiverParameter()     // Catch: java.lang.IllegalAccessException -> L39
            if (r0 == 0) goto Lf
            goto L30
        Lf:
            java.lang.RuntimeException r2 = new java.lang.RuntimeException     // Catch: java.lang.IllegalAccessException -> L39
            java.lang.StringBuilder r3 = new java.lang.StringBuilder     // Catch: java.lang.IllegalAccessException -> L39
            r3.<init>()     // Catch: java.lang.IllegalAccessException -> L39
            r0 = 39
            r3.append(r0)     // Catch: java.lang.IllegalAccessException -> L39
            r3.append(r1)     // Catch: java.lang.IllegalAccessException -> L39
            java.lang.String r0 = "' is not an extension property and thus getExtensionDelegate() "
            r3.append(r0)     // Catch: java.lang.IllegalAccessException -> L39
            java.lang.String r0 = "is not going to work, use getDelegate() instead"
            r3.append(r0)     // Catch: java.lang.IllegalAccessException -> L39
            java.lang.String r3 = r3.toString()     // Catch: java.lang.IllegalAccessException -> L39
            r2.<init>(r3)     // Catch: java.lang.IllegalAccessException -> L39
            throw r2     // Catch: java.lang.IllegalAccessException -> L39
        L30:
            if (r2 == 0) goto L37
            java.lang.Object r2 = r2.get(r3)     // Catch: java.lang.IllegalAccessException -> L39
            goto L38
        L37:
            r2 = 0
        L38:
            return r2
        L39:
            r2 = move-exception
            kotlin.reflect.full.IllegalPropertyDelegateAccessException r3 = new kotlin.reflect.full.IllegalPropertyDelegateAccessException
            r3.<init>(r2)
            throw r3
        */
        throw new UnsupportedOperationException("Method not decompiled: kotlin.reflect.jvm.internal.KPropertyImpl.getDelegate(java.lang.reflect.Field, java.lang.Object):java.lang.Object");
    }

    @NotNull
    public abstract Getter<V> getGetter();

    @Nullable
    public final Field getJavaField() {
        return this._javaField.invoke();
    }

    @Override // kotlin.reflect.KCallable
    @NotNull
    public String getName() {
        return this.name;
    }

    @NotNull
    public final String getSignature() {
        return this.signature;
    }

    public int hashCode() {
        return this.signature.hashCode() + ((getName().hashCode() + (getContainer().hashCode() * 31)) * 31);
    }

    @Override // kotlin.reflect.jvm.internal.KCallableImpl
    public boolean isBound() {
        return !Intrinsics.areEqual(this.rawBoundReceiver, CallableReference.NO_RECEIVER);
    }

    @Override // kotlin.reflect.KProperty
    public boolean isConst() {
        return getDescriptor().isConst();
    }

    @Override // kotlin.reflect.KProperty
    public boolean isLateinit() {
        return getDescriptor().isLateInit();
    }

    @Override // kotlin.reflect.KCallable
    public boolean isSuspend() {
        return false;
    }

    @NotNull
    public String toString() {
        return ReflectionObjectRenderer.INSTANCE.renderProperty(getDescriptor());
    }

    @Override // kotlin.reflect.jvm.internal.KCallableImpl
    @NotNull
    public PropertyDescriptor getDescriptor() {
        PropertyDescriptor invoke = this._descriptor.invoke();
        Intrinsics.checkNotNullExpressionValue(invoke, "_descriptor()");
        return invoke;
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public KPropertyImpl(@NotNull KDeclarationContainerImpl container, @NotNull String name, @NotNull String signature, @Nullable Object obj) {
        this(container, name, signature, null, obj);
        Intrinsics.checkNotNullParameter(container, "container");
        Intrinsics.checkNotNullParameter(name, "name");
        Intrinsics.checkNotNullParameter(signature, "signature");
    }

    /* JADX WARN: Illegal instructions before constructor call */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public KPropertyImpl(@org.jetbrains.annotations.NotNull kotlin.reflect.jvm.internal.KDeclarationContainerImpl r8, @org.jetbrains.annotations.NotNull kotlin.reflect.jvm.internal.impl.descriptors.PropertyDescriptor r9) {
        /*
            r7 = this;
            java.lang.String r0 = "container"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r8, r0)
            java.lang.String r0 = "descriptor"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r9, r0)
            kotlin.reflect.jvm.internal.impl.name.Name r0 = r9.getName()
            java.lang.String r3 = r0.asString()
            java.lang.String r0 = "descriptor.name.asString()"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r3, r0)
            kotlin.reflect.jvm.internal.RuntimeTypeMapper r0 = kotlin.reflect.jvm.internal.RuntimeTypeMapper.INSTANCE
            kotlin.reflect.jvm.internal.JvmPropertySignature r0 = r0.mapPropertySignature(r9)
            java.lang.String r4 = r0.getString()
            java.lang.Object r6 = kotlin.jvm.internal.CallableReference.NO_RECEIVER
            r1 = r7
            r2 = r8
            r5 = r9
            r1.<init>(r2, r3, r4, r5, r6)
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: kotlin.reflect.jvm.internal.KPropertyImpl.<init>(kotlin.reflect.jvm.internal.KDeclarationContainerImpl, kotlin.reflect.jvm.internal.impl.descriptors.PropertyDescriptor):void");
    }
}
