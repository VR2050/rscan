package kotlin.reflect.jvm.internal.impl.builtins;

import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import kotlin.collections.CollectionsKt__CollectionsKt;
import kotlin.collections.SetsKt__SetsKt;
import kotlin.jvm.JvmField;
import kotlin.jvm.JvmStatic;
import kotlin.jvm.internal.Intrinsics;
import kotlin.reflect.jvm.internal.impl.builtins.functions.FunctionClassKind;
import kotlin.reflect.jvm.internal.impl.name.ClassId;
import kotlin.reflect.jvm.internal.impl.name.FqName;
import kotlin.reflect.jvm.internal.impl.name.FqNameUnsafe;
import kotlin.reflect.jvm.internal.impl.name.Name;
import kotlin.reflect.jvm.internal.impl.utils.CollectionsKt;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public final class StandardNames {

    @JvmField
    @NotNull
    public static final FqName ANNOTATION_PACKAGE_FQ_NAME;

    @JvmField
    @NotNull
    public static final FqName BUILT_INS_PACKAGE_FQ_NAME;

    @JvmField
    @NotNull
    public static final Set<FqName> BUILT_INS_PACKAGE_FQ_NAMES;

    @JvmField
    @NotNull
    public static final Name BUILT_INS_PACKAGE_NAME;

    @JvmField
    @NotNull
    public static final Name CHAR_CODE;

    @JvmField
    @NotNull
    public static final FqName COLLECTIONS_PACKAGE_FQ_NAME;

    @JvmField
    @NotNull
    public static final FqName CONTINUATION_INTERFACE_FQ_NAME_EXPERIMENTAL;

    @JvmField
    @NotNull
    public static final FqName CONTINUATION_INTERFACE_FQ_NAME_RELEASE;

    @JvmField
    @NotNull
    public static final FqName COROUTINES_INTRINSICS_PACKAGE_FQ_NAME_EXPERIMENTAL;

    @JvmField
    @NotNull
    public static final FqName COROUTINES_PACKAGE_FQ_NAME_EXPERIMENTAL;

    @JvmField
    @NotNull
    public static final FqName COROUTINES_PACKAGE_FQ_NAME_RELEASE;

    @JvmField
    @NotNull
    public static final Name ENUM_VALUES;

    @JvmField
    @NotNull
    public static final Name ENUM_VALUE_OF;

    @NotNull
    public static final StandardNames INSTANCE = new StandardNames();

    @JvmField
    @NotNull
    public static final FqName KOTLIN_REFLECT_FQ_NAME;

    @JvmField
    @NotNull
    public static final List<String> PREFIXES;

    @JvmField
    @NotNull
    public static final FqName RANGES_PACKAGE_FQ_NAME;

    @JvmField
    @NotNull
    public static final FqName RESULT_FQ_NAME;

    @JvmField
    @NotNull
    public static final FqName TEXT_PACKAGE_FQ_NAME;

    public static final class FqNames {

        @NotNull
        public static final FqNames INSTANCE;

        @JvmField
        @NotNull
        public static final FqNameUnsafe _boolean;

        @JvmField
        @NotNull
        public static final FqNameUnsafe _byte;

        @JvmField
        @NotNull
        public static final FqNameUnsafe _char;

        @JvmField
        @NotNull
        public static final FqNameUnsafe _double;

        @JvmField
        @NotNull
        public static final FqNameUnsafe _enum;

        @JvmField
        @NotNull
        public static final FqNameUnsafe _float;

        @JvmField
        @NotNull
        public static final FqNameUnsafe _int;

        @JvmField
        @NotNull
        public static final FqNameUnsafe _long;

        @JvmField
        @NotNull
        public static final FqNameUnsafe _short;

        @JvmField
        @NotNull
        public static final FqName annotation;

        @JvmField
        @NotNull
        public static final FqName annotationRetention;

        @JvmField
        @NotNull
        public static final FqName annotationTarget;

        @JvmField
        @NotNull
        public static final FqNameUnsafe any;

        @JvmField
        @NotNull
        public static final FqNameUnsafe array;

        @JvmField
        @NotNull
        public static final Map<FqNameUnsafe, PrimitiveType> arrayClassFqNameToPrimitiveType;

        @JvmField
        @NotNull
        public static final FqNameUnsafe charSequence;

        @JvmField
        @NotNull
        public static final FqNameUnsafe cloneable;

        @JvmField
        @NotNull
        public static final FqName collection;

        @JvmField
        @NotNull
        public static final FqName comparable;

        @JvmField
        @NotNull
        public static final FqName deprecated;

        @JvmField
        @NotNull
        public static final FqName deprecatedSinceKotlin;

        @JvmField
        @NotNull
        public static final FqName deprecationLevel;

        @JvmField
        @NotNull
        public static final FqName extensionFunctionType;

        @JvmField
        @NotNull
        public static final Map<FqNameUnsafe, PrimitiveType> fqNameToPrimitiveType;

        @JvmField
        @NotNull
        public static final FqNameUnsafe functionSupertype;

        @JvmField
        @NotNull
        public static final FqNameUnsafe intRange;

        @JvmField
        @NotNull
        public static final FqName iterable;

        @JvmField
        @NotNull
        public static final FqName iterator;

        @JvmField
        @NotNull
        public static final FqNameUnsafe kCallable;

        @JvmField
        @NotNull
        public static final FqNameUnsafe kClass;

        @JvmField
        @NotNull
        public static final FqNameUnsafe kDeclarationContainer;

        @JvmField
        @NotNull
        public static final FqNameUnsafe kMutableProperty0;

        @JvmField
        @NotNull
        public static final FqNameUnsafe kMutableProperty1;

        @JvmField
        @NotNull
        public static final FqNameUnsafe kMutableProperty2;

        @JvmField
        @NotNull
        public static final FqNameUnsafe kMutablePropertyFqName;

        @JvmField
        @NotNull
        public static final ClassId kProperty;

        @JvmField
        @NotNull
        public static final FqNameUnsafe kProperty0;

        @JvmField
        @NotNull
        public static final FqNameUnsafe kProperty1;

        @JvmField
        @NotNull
        public static final FqNameUnsafe kProperty2;

        @JvmField
        @NotNull
        public static final FqNameUnsafe kPropertyFqName;

        @JvmField
        @NotNull
        public static final FqName list;

        @JvmField
        @NotNull
        public static final FqName listIterator;

        @JvmField
        @NotNull
        public static final FqNameUnsafe longRange;

        @JvmField
        @NotNull
        public static final FqName map;

        @JvmField
        @NotNull
        public static final FqName mapEntry;

        @JvmField
        @NotNull
        public static final FqName mustBeDocumented;

        @JvmField
        @NotNull
        public static final FqName mutableCollection;

        @JvmField
        @NotNull
        public static final FqName mutableIterable;

        @JvmField
        @NotNull
        public static final FqName mutableIterator;

        @JvmField
        @NotNull
        public static final FqName mutableList;

        @JvmField
        @NotNull
        public static final FqName mutableListIterator;

        @JvmField
        @NotNull
        public static final FqName mutableMap;

        @JvmField
        @NotNull
        public static final FqName mutableMapEntry;

        @JvmField
        @NotNull
        public static final FqName mutableSet;

        @JvmField
        @NotNull
        public static final FqNameUnsafe nothing;

        @JvmField
        @NotNull
        public static final FqNameUnsafe number;

        @JvmField
        @NotNull
        public static final FqName parameterName;

        @JvmField
        @NotNull
        public static final Set<Name> primitiveArrayTypeShortNames;

        @JvmField
        @NotNull
        public static final Set<Name> primitiveTypeShortNames;

        @JvmField
        @NotNull
        public static final FqName publishedApi;

        @JvmField
        @NotNull
        public static final FqName repeatable;

        @JvmField
        @NotNull
        public static final FqName replaceWith;

        @JvmField
        @NotNull
        public static final FqName retention;

        @JvmField
        @NotNull
        public static final FqName set;

        @JvmField
        @NotNull
        public static final FqNameUnsafe string;

        @JvmField
        @NotNull
        public static final FqName suppress;

        @JvmField
        @NotNull
        public static final FqName target;

        @JvmField
        @NotNull
        public static final FqName throwable;

        @JvmField
        @NotNull
        public static final ClassId uByte;

        @JvmField
        @NotNull
        public static final FqName uByteArrayFqName;

        @JvmField
        @NotNull
        public static final FqName uByteFqName;

        @JvmField
        @NotNull
        public static final ClassId uInt;

        @JvmField
        @NotNull
        public static final FqName uIntArrayFqName;

        @JvmField
        @NotNull
        public static final FqName uIntFqName;

        @JvmField
        @NotNull
        public static final ClassId uLong;

        @JvmField
        @NotNull
        public static final FqName uLongArrayFqName;

        @JvmField
        @NotNull
        public static final FqName uLongFqName;

        @JvmField
        @NotNull
        public static final ClassId uShort;

        @JvmField
        @NotNull
        public static final FqName uShortArrayFqName;

        @JvmField
        @NotNull
        public static final FqName uShortFqName;

        @JvmField
        @NotNull
        public static final FqNameUnsafe unit;

        @JvmField
        @NotNull
        public static final FqName unsafeVariance;

        static {
            FqNames fqNames = new FqNames();
            INSTANCE = fqNames;
            any = fqNames.fqNameUnsafe("Any");
            nothing = fqNames.fqNameUnsafe("Nothing");
            cloneable = fqNames.fqNameUnsafe("Cloneable");
            suppress = fqNames.fqName("Suppress");
            unit = fqNames.fqNameUnsafe("Unit");
            charSequence = fqNames.fqNameUnsafe("CharSequence");
            string = fqNames.fqNameUnsafe("String");
            array = fqNames.fqNameUnsafe("Array");
            _boolean = fqNames.fqNameUnsafe("Boolean");
            _char = fqNames.fqNameUnsafe("Char");
            _byte = fqNames.fqNameUnsafe("Byte");
            _short = fqNames.fqNameUnsafe("Short");
            _int = fqNames.fqNameUnsafe("Int");
            _long = fqNames.fqNameUnsafe("Long");
            _float = fqNames.fqNameUnsafe("Float");
            _double = fqNames.fqNameUnsafe("Double");
            number = fqNames.fqNameUnsafe("Number");
            _enum = fqNames.fqNameUnsafe("Enum");
            functionSupertype = fqNames.fqNameUnsafe("Function");
            throwable = fqNames.fqName("Throwable");
            comparable = fqNames.fqName("Comparable");
            intRange = fqNames.rangesFqName("IntRange");
            longRange = fqNames.rangesFqName("LongRange");
            deprecated = fqNames.fqName("Deprecated");
            deprecatedSinceKotlin = fqNames.fqName("DeprecatedSinceKotlin");
            deprecationLevel = fqNames.fqName("DeprecationLevel");
            replaceWith = fqNames.fqName("ReplaceWith");
            extensionFunctionType = fqNames.fqName("ExtensionFunctionType");
            parameterName = fqNames.fqName("ParameterName");
            annotation = fqNames.fqName("Annotation");
            target = fqNames.annotationName("Target");
            annotationTarget = fqNames.annotationName("AnnotationTarget");
            annotationRetention = fqNames.annotationName("AnnotationRetention");
            retention = fqNames.annotationName("Retention");
            repeatable = fqNames.annotationName("Repeatable");
            mustBeDocumented = fqNames.annotationName("MustBeDocumented");
            unsafeVariance = fqNames.fqName("UnsafeVariance");
            publishedApi = fqNames.fqName("PublishedApi");
            iterator = fqNames.collectionsFqName("Iterator");
            iterable = fqNames.collectionsFqName("Iterable");
            collection = fqNames.collectionsFqName("Collection");
            list = fqNames.collectionsFqName("List");
            listIterator = fqNames.collectionsFqName("ListIterator");
            set = fqNames.collectionsFqName("Set");
            FqName collectionsFqName = fqNames.collectionsFqName("Map");
            map = collectionsFqName;
            FqName child = collectionsFqName.child(Name.identifier("Entry"));
            Intrinsics.checkNotNullExpressionValue(child, "map.child(Name.identifier(\"Entry\"))");
            mapEntry = child;
            mutableIterator = fqNames.collectionsFqName("MutableIterator");
            mutableIterable = fqNames.collectionsFqName("MutableIterable");
            mutableCollection = fqNames.collectionsFqName("MutableCollection");
            mutableList = fqNames.collectionsFqName("MutableList");
            FqNames fqNames2 = INSTANCE;
            mutableListIterator = fqNames2.collectionsFqName("MutableListIterator");
            mutableSet = fqNames2.collectionsFqName("MutableSet");
            FqName collectionsFqName2 = fqNames2.collectionsFqName("MutableMap");
            mutableMap = collectionsFqName2;
            FqName child2 = collectionsFqName2.child(Name.identifier("MutableEntry"));
            Intrinsics.checkNotNullExpressionValue(child2, "mutableMap.child(Name.identifier(\"MutableEntry\"))");
            mutableMapEntry = child2;
            kClass = reflect("KClass");
            kCallable = reflect("KCallable");
            kProperty0 = reflect("KProperty0");
            kProperty1 = reflect("KProperty1");
            kProperty2 = reflect("KProperty2");
            kMutableProperty0 = reflect("KMutableProperty0");
            kMutableProperty1 = reflect("KMutableProperty1");
            kMutableProperty2 = reflect("KMutableProperty2");
            FqNameUnsafe reflect = reflect("KProperty");
            kPropertyFqName = reflect;
            kMutablePropertyFqName = reflect("KMutableProperty");
            ClassId classId = ClassId.topLevel(reflect.toSafe());
            Intrinsics.checkNotNullExpressionValue(classId, "topLevel(kPropertyFqName.toSafe())");
            kProperty = classId;
            kDeclarationContainer = reflect("KDeclarationContainer");
            FqName fqName = fqNames2.fqName("UByte");
            uByteFqName = fqName;
            FqName fqName2 = fqNames2.fqName("UShort");
            uShortFqName = fqName2;
            FqName fqName3 = fqNames2.fqName("UInt");
            uIntFqName = fqName3;
            FqName fqName4 = fqNames2.fqName("ULong");
            uLongFqName = fqName4;
            ClassId classId2 = ClassId.topLevel(fqName);
            Intrinsics.checkNotNullExpressionValue(classId2, "topLevel(uByteFqName)");
            uByte = classId2;
            ClassId classId3 = ClassId.topLevel(fqName2);
            Intrinsics.checkNotNullExpressionValue(classId3, "topLevel(uShortFqName)");
            uShort = classId3;
            ClassId classId4 = ClassId.topLevel(fqName3);
            Intrinsics.checkNotNullExpressionValue(classId4, "topLevel(uIntFqName)");
            uInt = classId4;
            ClassId classId5 = ClassId.topLevel(fqName4);
            Intrinsics.checkNotNullExpressionValue(classId5, "topLevel(uLongFqName)");
            uLong = classId5;
            uByteArrayFqName = fqNames2.fqName("UByteArray");
            uShortArrayFqName = fqNames2.fqName("UShortArray");
            uIntArrayFqName = fqNames2.fqName("UIntArray");
            uLongArrayFqName = fqNames2.fqName("ULongArray");
            PrimitiveType.values();
            HashSet newHashSetWithExpectedSize = CollectionsKt.newHashSetWithExpectedSize(8);
            PrimitiveType[] values = PrimitiveType.values();
            int i2 = 0;
            for (int i3 = 0; i3 < 8; i3++) {
                newHashSetWithExpectedSize.add(values[i3].getTypeName());
            }
            primitiveTypeShortNames = newHashSetWithExpectedSize;
            PrimitiveType.values();
            HashSet newHashSetWithExpectedSize2 = CollectionsKt.newHashSetWithExpectedSize(8);
            PrimitiveType[] values2 = PrimitiveType.values();
            for (int i4 = 0; i4 < 8; i4++) {
                newHashSetWithExpectedSize2.add(values2[i4].getArrayTypeName());
            }
            primitiveArrayTypeShortNames = newHashSetWithExpectedSize2;
            PrimitiveType.values();
            HashMap newHashMapWithExpectedSize = CollectionsKt.newHashMapWithExpectedSize(8);
            PrimitiveType[] values3 = PrimitiveType.values();
            int i5 = 0;
            while (i5 < 8) {
                PrimitiveType primitiveType = values3[i5];
                i5++;
                FqNames fqNames3 = INSTANCE;
                String asString = primitiveType.getTypeName().asString();
                Intrinsics.checkNotNullExpressionValue(asString, "primitiveType.typeName.asString()");
                newHashMapWithExpectedSize.put(fqNames3.fqNameUnsafe(asString), primitiveType);
            }
            fqNameToPrimitiveType = newHashMapWithExpectedSize;
            PrimitiveType.values();
            HashMap newHashMapWithExpectedSize2 = CollectionsKt.newHashMapWithExpectedSize(8);
            PrimitiveType[] values4 = PrimitiveType.values();
            while (i2 < 8) {
                PrimitiveType primitiveType2 = values4[i2];
                i2++;
                FqNames fqNames4 = INSTANCE;
                String asString2 = primitiveType2.getArrayTypeName().asString();
                Intrinsics.checkNotNullExpressionValue(asString2, "primitiveType.arrayTypeName.asString()");
                newHashMapWithExpectedSize2.put(fqNames4.fqNameUnsafe(asString2), primitiveType2);
            }
            arrayClassFqNameToPrimitiveType = newHashMapWithExpectedSize2;
        }

        private FqNames() {
        }

        private final FqName annotationName(String str) {
            FqName child = StandardNames.ANNOTATION_PACKAGE_FQ_NAME.child(Name.identifier(str));
            Intrinsics.checkNotNullExpressionValue(child, "ANNOTATION_PACKAGE_FQ_NAME.child(Name.identifier(simpleName))");
            return child;
        }

        private final FqName collectionsFqName(String str) {
            FqName child = StandardNames.COLLECTIONS_PACKAGE_FQ_NAME.child(Name.identifier(str));
            Intrinsics.checkNotNullExpressionValue(child, "COLLECTIONS_PACKAGE_FQ_NAME.child(Name.identifier(simpleName))");
            return child;
        }

        private final FqName fqName(String str) {
            FqName child = StandardNames.BUILT_INS_PACKAGE_FQ_NAME.child(Name.identifier(str));
            Intrinsics.checkNotNullExpressionValue(child, "BUILT_INS_PACKAGE_FQ_NAME.child(Name.identifier(simpleName))");
            return child;
        }

        private final FqNameUnsafe fqNameUnsafe(String str) {
            FqNameUnsafe unsafe = fqName(str).toUnsafe();
            Intrinsics.checkNotNullExpressionValue(unsafe, "fqName(simpleName).toUnsafe()");
            return unsafe;
        }

        private final FqNameUnsafe rangesFqName(String str) {
            FqNameUnsafe unsafe = StandardNames.RANGES_PACKAGE_FQ_NAME.child(Name.identifier(str)).toUnsafe();
            Intrinsics.checkNotNullExpressionValue(unsafe, "RANGES_PACKAGE_FQ_NAME.child(Name.identifier(simpleName)).toUnsafe()");
            return unsafe;
        }

        @JvmStatic
        @NotNull
        public static final FqNameUnsafe reflect(@NotNull String simpleName) {
            Intrinsics.checkNotNullParameter(simpleName, "simpleName");
            FqNameUnsafe unsafe = StandardNames.KOTLIN_REFLECT_FQ_NAME.child(Name.identifier(simpleName)).toUnsafe();
            Intrinsics.checkNotNullExpressionValue(unsafe, "KOTLIN_REFLECT_FQ_NAME.child(Name.identifier(simpleName)).toUnsafe()");
            return unsafe;
        }
    }

    static {
        Name identifier = Name.identifier("values");
        Intrinsics.checkNotNullExpressionValue(identifier, "identifier(\"values\")");
        ENUM_VALUES = identifier;
        Name identifier2 = Name.identifier("valueOf");
        Intrinsics.checkNotNullExpressionValue(identifier2, "identifier(\"valueOf\")");
        ENUM_VALUE_OF = identifier2;
        Name identifier3 = Name.identifier("code");
        Intrinsics.checkNotNullExpressionValue(identifier3, "identifier(\"code\")");
        CHAR_CODE = identifier3;
        FqName fqName = new FqName("kotlin.coroutines");
        COROUTINES_PACKAGE_FQ_NAME_RELEASE = fqName;
        FqName child = fqName.child(Name.identifier("experimental"));
        Intrinsics.checkNotNullExpressionValue(child, "COROUTINES_PACKAGE_FQ_NAME_RELEASE.child(Name.identifier(\"experimental\"))");
        COROUTINES_PACKAGE_FQ_NAME_EXPERIMENTAL = child;
        FqName child2 = child.child(Name.identifier("intrinsics"));
        Intrinsics.checkNotNullExpressionValue(child2, "COROUTINES_PACKAGE_FQ_NAME_EXPERIMENTAL.child(Name.identifier(\"intrinsics\"))");
        COROUTINES_INTRINSICS_PACKAGE_FQ_NAME_EXPERIMENTAL = child2;
        FqName child3 = child.child(Name.identifier("Continuation"));
        Intrinsics.checkNotNullExpressionValue(child3, "COROUTINES_PACKAGE_FQ_NAME_EXPERIMENTAL.child(Name.identifier(\"Continuation\"))");
        CONTINUATION_INTERFACE_FQ_NAME_EXPERIMENTAL = child3;
        FqName child4 = fqName.child(Name.identifier("Continuation"));
        Intrinsics.checkNotNullExpressionValue(child4, "COROUTINES_PACKAGE_FQ_NAME_RELEASE.child(Name.identifier(\"Continuation\"))");
        CONTINUATION_INTERFACE_FQ_NAME_RELEASE = child4;
        RESULT_FQ_NAME = new FqName("kotlin.Result");
        FqName fqName2 = new FqName("kotlin.reflect");
        KOTLIN_REFLECT_FQ_NAME = fqName2;
        PREFIXES = CollectionsKt__CollectionsKt.listOf((Object[]) new String[]{"KProperty", "KMutableProperty", "KFunction", "KSuspendFunction"});
        Name identifier4 = Name.identifier("kotlin");
        Intrinsics.checkNotNullExpressionValue(identifier4, "identifier(\"kotlin\")");
        BUILT_INS_PACKAGE_NAME = identifier4;
        FqName fqName3 = FqName.topLevel(identifier4);
        Intrinsics.checkNotNullExpressionValue(fqName3, "topLevel(BUILT_INS_PACKAGE_NAME)");
        BUILT_INS_PACKAGE_FQ_NAME = fqName3;
        FqName child5 = fqName3.child(Name.identifier("annotation"));
        Intrinsics.checkNotNullExpressionValue(child5, "BUILT_INS_PACKAGE_FQ_NAME.child(Name.identifier(\"annotation\"))");
        ANNOTATION_PACKAGE_FQ_NAME = child5;
        FqName child6 = fqName3.child(Name.identifier("collections"));
        Intrinsics.checkNotNullExpressionValue(child6, "BUILT_INS_PACKAGE_FQ_NAME.child(Name.identifier(\"collections\"))");
        COLLECTIONS_PACKAGE_FQ_NAME = child6;
        FqName child7 = fqName3.child(Name.identifier("ranges"));
        Intrinsics.checkNotNullExpressionValue(child7, "BUILT_INS_PACKAGE_FQ_NAME.child(Name.identifier(\"ranges\"))");
        RANGES_PACKAGE_FQ_NAME = child7;
        FqName child8 = fqName3.child(Name.identifier("text"));
        Intrinsics.checkNotNullExpressionValue(child8, "BUILT_INS_PACKAGE_FQ_NAME.child(Name.identifier(\"text\"))");
        TEXT_PACKAGE_FQ_NAME = child8;
        FqName child9 = fqName3.child(Name.identifier("internal"));
        Intrinsics.checkNotNullExpressionValue(child9, "BUILT_INS_PACKAGE_FQ_NAME.child(Name.identifier(\"internal\"))");
        BUILT_INS_PACKAGE_FQ_NAMES = SetsKt__SetsKt.setOf((Object[]) new FqName[]{fqName3, child6, child7, child5, fqName2, child9, fqName});
    }

    private StandardNames() {
    }

    @JvmStatic
    @NotNull
    public static final ClassId getFunctionClassId(int i2) {
        return new ClassId(BUILT_INS_PACKAGE_FQ_NAME, Name.identifier(getFunctionName(i2)));
    }

    @JvmStatic
    @NotNull
    public static final String getFunctionName(int i2) {
        return Intrinsics.stringPlus("Function", Integer.valueOf(i2));
    }

    @JvmStatic
    @NotNull
    public static final FqName getPrimitiveFqName(@NotNull PrimitiveType primitiveType) {
        Intrinsics.checkNotNullParameter(primitiveType, "primitiveType");
        FqName child = BUILT_INS_PACKAGE_FQ_NAME.child(primitiveType.getTypeName());
        Intrinsics.checkNotNullExpressionValue(child, "BUILT_INS_PACKAGE_FQ_NAME.child(primitiveType.typeName)");
        return child;
    }

    @JvmStatic
    @NotNull
    public static final String getSuspendFunctionName(int i2) {
        return Intrinsics.stringPlus(FunctionClassKind.SuspendFunction.getClassNamePrefix(), Integer.valueOf(i2));
    }

    @JvmStatic
    public static final boolean isPrimitiveArray(@NotNull FqNameUnsafe arrayFqName) {
        Intrinsics.checkNotNullParameter(arrayFqName, "arrayFqName");
        return FqNames.arrayClassFqNameToPrimitiveType.get(arrayFqName) != null;
    }
}
