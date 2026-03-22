package com.lljjcoder.style.citylist.sortlistview;

import java.util.Comparator;

/* loaded from: classes2.dex */
public class PinyinComparator implements Comparator<SortModel> {
    @Override // java.util.Comparator
    public int compare(SortModel sortModel, SortModel sortModel2) {
        if (sortModel.getSortLetters().equals("@") || sortModel2.getSortLetters().equals("#")) {
            return -1;
        }
        if (sortModel.getSortLetters().equals("#") || sortModel2.getSortLetters().equals("@")) {
            return 1;
        }
        return sortModel.getSortLetters().compareTo(sortModel2.getSortLetters());
    }
}
