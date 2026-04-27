package com.google.android.datatransport.runtime.util;

import android.util.SparseArray;
import com.google.android.datatransport.Priority;
import java.util.EnumMap;

/* JADX INFO: compiled from: com.google.android.datatransport:transport-runtime@@2.2.0 */
/* JADX INFO: loaded from: classes.dex */
public final class PriorityMapping {
    private static EnumMap<Priority, Integer> PRIORITY_INT_MAP;
    private static SparseArray<Priority> PRIORITY_MAP = new SparseArray<>();

    static {
        EnumMap<Priority, Integer> enumMap = new EnumMap<>(Priority.class);
        PRIORITY_INT_MAP = enumMap;
        enumMap.put(Priority.DEFAULT, 0);
        PRIORITY_INT_MAP.put(Priority.VERY_LOW, 1);
        PRIORITY_INT_MAP.put(Priority.HIGHEST, 2);
        for (K p : PRIORITY_INT_MAP.keySet()) {
            PRIORITY_MAP.append(PRIORITY_INT_MAP.get(p).intValue(), p);
        }
    }

    public static Priority valueOf(int value) {
        Priority priority = PRIORITY_MAP.get(value);
        if (priority == null) {
            throw new IllegalArgumentException("Unknown Priority for value " + value);
        }
        return priority;
    }

    public static int toInt(Priority priority) {
        Integer integer = PRIORITY_INT_MAP.get(priority);
        if (integer == null) {
            throw new IllegalStateException("PriorityMapping is missing known Priority value " + priority);
        }
        return integer.intValue();
    }
}
