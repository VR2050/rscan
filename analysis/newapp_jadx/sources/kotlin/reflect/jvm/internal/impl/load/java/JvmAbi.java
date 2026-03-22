package kotlin.reflect.jvm.internal.impl.load.java;

import kotlin.jvm.JvmField;
import kotlin.jvm.JvmStatic;
import kotlin.jvm.internal.Intrinsics;
import kotlin.reflect.jvm.internal.impl.name.ClassId;
import kotlin.reflect.jvm.internal.impl.name.FqName;
import kotlin.reflect.jvm.internal.impl.util.capitalizeDecapitalize.CapitalizeDecapitalizeKt;
import kotlin.text.StringsKt__StringsJVMKt;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public final class JvmAbi {

    @NotNull
    public static final JvmAbi INSTANCE = new JvmAbi();

    @JvmField
    @NotNull
    public static final FqName JVM_FIELD_ANNOTATION_FQ_NAME = new FqName("kotlin.jvm.JvmField");

    @NotNull
    private static final ClassId REFLECTION_FACTORY_IMPL;

    static {
        ClassId classId = ClassId.topLevel(new FqName("kotlin.reflect.jvm.internal.ReflectionFactoryImpl"));
        Intrinsics.checkNotNullExpressionValue(classId, "topLevel(FqName(\"kotlin.reflect.jvm.internal.ReflectionFactoryImpl\"))");
        REFLECTION_FACTORY_IMPL = classId;
    }

    private JvmAbi() {
    }

    @JvmStatic
    @NotNull
    public static final String getterName(@NotNull String propertyName) {
        Intrinsics.checkNotNullParameter(propertyName, "propertyName");
        return startsWithIsPrefix(propertyName) ? propertyName : Intrinsics.stringPlus("get", CapitalizeDecapitalizeKt.capitalizeAsciiOnly(propertyName));
    }

    @JvmStatic
    public static final boolean isGetterName(@NotNull String name) {
        Intrinsics.checkNotNullParameter(name, "name");
        return StringsKt__StringsJVMKt.startsWith$default(name, "get", false, 2, null) || StringsKt__StringsJVMKt.startsWith$default(name, "is", false, 2, null);
    }

    @JvmStatic
    public static final boolean isSetterName(@NotNull String name) {
        Intrinsics.checkNotNullParameter(name, "name");
        return StringsKt__StringsJVMKt.startsWith$default(name, "set", false, 2, null);
    }

    @JvmStatic
    @NotNull
    public static final String setterName(@NotNull String propertyName) {
        String capitalizeAsciiOnly;
        Intrinsics.checkNotNullParameter(propertyName, "propertyName");
        if (startsWithIsPrefix(propertyName)) {
            capitalizeAsciiOnly = propertyName.substring(2);
            Intrinsics.checkNotNullExpressionValue(capitalizeAsciiOnly, "(this as java.lang.String).substring(startIndex)");
        } else {
            capitalizeAsciiOnly = CapitalizeDecapitalizeKt.capitalizeAsciiOnly(propertyName);
        }
        return Intrinsics.stringPlus("set", capitalizeAsciiOnly);
    }

    @JvmStatic
    public static final boolean startsWithIsPrefix(@NotNull String name) {
        Intrinsics.checkNotNullParameter(name, "name");
        if (!StringsKt__StringsJVMKt.startsWith$default(name, "is", false, 2, null) || name.length() == 2) {
            return false;
        }
        char charAt = name.charAt(2);
        return Intrinsics.compare(97, (int) charAt) > 0 || Intrinsics.compare((int) charAt, 122) > 0;
    }
}
