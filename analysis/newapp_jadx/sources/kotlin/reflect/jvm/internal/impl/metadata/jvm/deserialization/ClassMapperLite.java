package kotlin.reflect.jvm.internal.impl.metadata.jvm.deserialization;

import androidx.exifinterface.media.ExifInterface;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import kotlin.collections.CollectionsKt__CollectionsKt;
import kotlin.collections.CollectionsKt___CollectionsKt;
import kotlin.internal.ProgressionUtilKt;
import kotlin.jvm.JvmStatic;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt__StringsJVMKt;
import kotlin.text.Typography;
import org.jetbrains.annotations.NotNull;
import p005b.p131d.p132a.p133a.C1499a;

/* loaded from: classes.dex */
public final class ClassMapperLite {

    @NotNull
    public static final ClassMapperLite INSTANCE = new ClassMapperLite();

    /* renamed from: kotlin, reason: collision with root package name */
    @NotNull
    private static final String f13029kotlin = CollectionsKt___CollectionsKt.joinToString$default(CollectionsKt__CollectionsKt.listOf((Object[]) new Character[]{'k', 'o', 't', 'l', 'i', 'n'}), "", null, null, 0, null, null, 62, null);

    @NotNull
    private static final Map<String, String> map;

    static {
        int i2 = 0;
        LinkedHashMap linkedHashMap = new LinkedHashMap();
        List listOf = CollectionsKt__CollectionsKt.listOf((Object[]) new String[]{"Boolean", "Z", "Char", "C", "Byte", "B", "Short", ExifInterface.LATITUDE_SOUTH, "Int", "I", "Float", "F", "Long", "J", "Double", "D"});
        int progressionLastElement = ProgressionUtilKt.getProgressionLastElement(0, listOf.size() - 1, 2);
        if (progressionLastElement >= 0) {
            int i3 = 0;
            while (true) {
                int i4 = i3 + 2;
                StringBuilder sb = new StringBuilder();
                String str = f13029kotlin;
                sb.append(str);
                sb.append('/');
                sb.append((String) listOf.get(i3));
                int i5 = i3 + 1;
                linkedHashMap.put(sb.toString(), listOf.get(i5));
                StringBuilder sb2 = new StringBuilder();
                sb2.append(str);
                sb2.append('/');
                linkedHashMap.put(C1499a.m582D(sb2, (String) listOf.get(i3), "Array"), Intrinsics.stringPlus("[", listOf.get(i5)));
                if (i3 == progressionLastElement) {
                    break;
                } else {
                    i3 = i4;
                }
            }
        }
        linkedHashMap.put(Intrinsics.stringPlus(f13029kotlin, "/Unit"), ExifInterface.GPS_MEASUREMENT_INTERRUPTED);
        m7309map$lambda0$add(linkedHashMap, "Any", "java/lang/Object");
        m7309map$lambda0$add(linkedHashMap, "Nothing", "java/lang/Void");
        m7309map$lambda0$add(linkedHashMap, "Annotation", "java/lang/annotation/Annotation");
        for (String str2 : CollectionsKt__CollectionsKt.listOf((Object[]) new String[]{"String", "CharSequence", "Throwable", "Cloneable", "Number", "Comparable", "Enum"})) {
            m7309map$lambda0$add(linkedHashMap, str2, Intrinsics.stringPlus("java/lang/", str2));
        }
        for (String str3 : CollectionsKt__CollectionsKt.listOf((Object[]) new String[]{"Iterator", "Collection", "List", "Set", "Map", "ListIterator"})) {
            m7309map$lambda0$add(linkedHashMap, Intrinsics.stringPlus("collections/", str3), Intrinsics.stringPlus("java/util/", str3));
            m7309map$lambda0$add(linkedHashMap, Intrinsics.stringPlus("collections/Mutable", str3), Intrinsics.stringPlus("java/util/", str3));
        }
        m7309map$lambda0$add(linkedHashMap, "collections/Iterable", "java/lang/Iterable");
        m7309map$lambda0$add(linkedHashMap, "collections/MutableIterable", "java/lang/Iterable");
        m7309map$lambda0$add(linkedHashMap, "collections/Map.Entry", "java/util/Map$Entry");
        m7309map$lambda0$add(linkedHashMap, "collections/MutableMap.MutableEntry", "java/util/Map$Entry");
        while (true) {
            int i6 = i2 + 1;
            String stringPlus = Intrinsics.stringPlus("Function", Integer.valueOf(i2));
            StringBuilder sb3 = new StringBuilder();
            String str4 = f13029kotlin;
            sb3.append(str4);
            sb3.append("/jvm/functions/Function");
            sb3.append(i2);
            m7309map$lambda0$add(linkedHashMap, stringPlus, sb3.toString());
            m7309map$lambda0$add(linkedHashMap, Intrinsics.stringPlus("reflect/KFunction", Integer.valueOf(i2)), Intrinsics.stringPlus(str4, "/reflect/KFunction"));
            if (i6 > 22) {
                break;
            } else {
                i2 = i6;
            }
        }
        for (String str5 : CollectionsKt__CollectionsKt.listOf((Object[]) new String[]{"Char", "Byte", "Short", "Int", "Float", "Long", "Double", "String", "Enum"})) {
            m7309map$lambda0$add(linkedHashMap, Intrinsics.stringPlus(str5, ".Companion"), f13029kotlin + "/jvm/internal/" + str5 + "CompanionObject");
        }
        map = linkedHashMap;
    }

    private ClassMapperLite() {
    }

    /* renamed from: map$lambda-0$add, reason: not valid java name */
    private static final void m7309map$lambda0$add(Map<String, String> map2, String str, String str2) {
        map2.put(f13029kotlin + '/' + str, 'L' + str2 + ';');
    }

    @JvmStatic
    @NotNull
    public static final String mapClass(@NotNull String classId) {
        Intrinsics.checkNotNullParameter(classId, "classId");
        String str = map.get(classId);
        return str == null ? C1499a.m581C(C1499a.m584F('L'), StringsKt__StringsJVMKt.replace$default(classId, '.', Typography.dollar, false, 4, (Object) null), ';') : str;
    }
}
