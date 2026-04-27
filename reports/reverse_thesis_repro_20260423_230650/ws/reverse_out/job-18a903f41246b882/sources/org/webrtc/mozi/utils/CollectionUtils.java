package org.webrtc.mozi.utils;

import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedList;
import java.util.List;
import java.util.function.ToIntFunction;
import java.util.function.ToLongFunction;

/* JADX INFO: loaded from: classes3.dex */
public class CollectionUtils {
    public static boolean isEmpty(Collection collection) {
        return collection == null || collection.isEmpty();
    }

    public static int size(Collection collection) {
        if (collection == null) {
            return 0;
        }
        return collection.size();
    }

    public static <T> void sortPriority(List<T> list, final ToIntFunction<T> priorityFunction) {
        if (priorityFunction == null) {
            return;
        }
        Collections.sort(list, new Comparator<T>() { // from class: org.webrtc.mozi.utils.CollectionUtils.1
            @Override // java.util.Comparator
            public int compare(T o1, T o2) {
                return priorityFunction.applyAsInt(o2) - priorityFunction.applyAsInt(o1);
            }
        });
    }

    public static <T> void sortPriority(List<T> list, final ToLongFunction<T> priorityFunction) {
        if (priorityFunction == null) {
            return;
        }
        Collections.sort(list, new Comparator<T>() { // from class: org.webrtc.mozi.utils.CollectionUtils.2
            @Override // java.util.Comparator
            public int compare(T o1, T o2) {
                long p1 = priorityFunction.applyAsLong(o1);
                long p2 = priorityFunction.applyAsLong(o2);
                if (p1 == p2) {
                    return 0;
                }
                return p1 > p2 ? -1 : 1;
            }
        });
    }

    public static <T> List<T> safeCast(List<? extends T> srcList) {
        if (srcList == null) {
            return null;
        }
        List<T> destList = new LinkedList<>();
        for (T src : srcList) {
            if (src != null) {
                destList.add(src);
            }
        }
        return destList;
    }

    public static <T> T getOrNull(List<T> list, int index) {
        if (index >= 0 && index < list.size()) {
            return list.get(index);
        }
        return null;
    }

    public static boolean equalsIgnoreOrder(List<String> list1, List<String> list2) {
        if (list1 == list2) {
            return true;
        }
        if (list1 != null && list2 != null) {
            Collections.sort(list1);
            Collections.sort(list2);
            return list1.equals(list2);
        }
        return false;
    }

    public static <T> String toString(List<T> list) {
        if (list == null) {
            return "null";
        }
        StringBuilder sb = new StringBuilder("[");
        if (list.size() > 0) {
            for (int i = 0; i < list.size(); i++) {
                sb.append(list.get(i).toString());
                if (i < list.size() - 1) {
                    sb.append(",");
                }
            }
        }
        sb.append("]");
        return sb.toString();
    }
}
