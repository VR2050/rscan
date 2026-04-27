package r2;

import t2.d;
import t2.j;

/* JADX INFO: renamed from: r2.a, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public abstract class AbstractC0677a {
    public static final Class a(x2.b bVar) {
        j.f(bVar, "<this>");
        Class clsA = ((d) bVar).a();
        j.d(clsA, "null cannot be cast to non-null type java.lang.Class<T of kotlin.jvm.JvmClassMappingKt.<get-java>>");
        return clsA;
    }

    /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue */
    public static final Class b(x2.b bVar) {
        j.f(bVar, "<this>");
        Class clsA = ((d) bVar).a();
        if (!clsA.isPrimitive()) {
            j.d(clsA, "null cannot be cast to non-null type java.lang.Class<T of kotlin.jvm.JvmClassMappingKt.<get-javaObjectType>>");
            return clsA;
        }
        String name = clsA.getName();
        switch (name.hashCode()) {
            case -1325958191:
                if (name.equals("double")) {
                    clsA = Double.class;
                }
                break;
            case 104431:
                if (name.equals("int")) {
                    clsA = Integer.class;
                }
                break;
            case 3039496:
                if (name.equals("byte")) {
                    clsA = Byte.class;
                }
                break;
            case 3052374:
                if (name.equals("char")) {
                    clsA = Character.class;
                }
                break;
            case 3327612:
                if (name.equals("long")) {
                    clsA = Long.class;
                }
                break;
            case 3625364:
                if (name.equals("void")) {
                    clsA = Void.class;
                }
                break;
            case 64711720:
                if (name.equals("boolean")) {
                    clsA = Boolean.class;
                }
                break;
            case 97526364:
                if (name.equals("float")) {
                    clsA = Float.class;
                }
                break;
            case 109413500:
                if (name.equals("short")) {
                    clsA = Short.class;
                }
                break;
        }
        j.d(clsA, "null cannot be cast to non-null type java.lang.Class<T of kotlin.jvm.JvmClassMappingKt.<get-javaObjectType>>");
        return clsA;
    }
}
