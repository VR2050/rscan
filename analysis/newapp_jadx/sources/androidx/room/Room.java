package androidx.room;

import android.content.Context;
import androidx.annotation.NonNull;
import androidx.room.RoomDatabase;
import p005b.p131d.p132a.p133a.C1499a;

/* loaded from: classes.dex */
public class Room {
    private static final String CURSOR_CONV_SUFFIX = "_CursorConverter";
    public static final String LOG_TAG = "ROOM";
    public static final String MASTER_TABLE_NAME = "room_master_table";

    @Deprecated
    public Room() {
    }

    @NonNull
    public static <T extends RoomDatabase> RoomDatabase.Builder<T> databaseBuilder(@NonNull Context context, @NonNull Class<T> cls, @NonNull String str) {
        if (str == null || str.trim().length() == 0) {
            throw new IllegalArgumentException("Cannot build a database with null or empty name. If you are trying to create an in memory database, use Room.inMemoryDatabaseBuilder");
        }
        return new RoomDatabase.Builder<>(context, cls, str);
    }

    @NonNull
    public static <T, C> T getGeneratedImplementation(Class<C> cls, String str) {
        String str2;
        String name = cls.getPackage().getName();
        String canonicalName = cls.getCanonicalName();
        if (!name.isEmpty()) {
            canonicalName = canonicalName.substring(name.length() + 1);
        }
        String str3 = canonicalName.replace('.', '_') + str;
        try {
            if (name.isEmpty()) {
                str2 = str3;
            } else {
                str2 = name + "." + str3;
            }
            return (T) Class.forName(str2).newInstance();
        } catch (ClassNotFoundException unused) {
            StringBuilder m586H = C1499a.m586H("cannot find implementation for ");
            m586H.append(cls.getCanonicalName());
            m586H.append(". ");
            m586H.append(str3);
            m586H.append(" does not exist");
            throw new RuntimeException(m586H.toString());
        } catch (IllegalAccessException unused2) {
            StringBuilder m586H2 = C1499a.m586H("Cannot access the constructor");
            m586H2.append(cls.getCanonicalName());
            throw new RuntimeException(m586H2.toString());
        } catch (InstantiationException unused3) {
            StringBuilder m586H3 = C1499a.m586H("Failed to create an instance of ");
            m586H3.append(cls.getCanonicalName());
            throw new RuntimeException(m586H3.toString());
        }
    }

    @NonNull
    public static <T extends RoomDatabase> RoomDatabase.Builder<T> inMemoryDatabaseBuilder(@NonNull Context context, @NonNull Class<T> cls) {
        return new RoomDatabase.Builder<>(context, cls, null);
    }
}
