package com.googlecode.mp4parser.util;

import com.litesuits.orm.db.assit.SQLBuilder;

/* JADX INFO: loaded from: classes.dex */
public class CastUtils {
    public static int l2i(long l) {
        if (l > 2147483647L || l < -2147483648L) {
            throw new RuntimeException("A cast to int has gone wrong. Please contact the mp4parser discussion group (" + l + SQLBuilder.PARENTHESES_RIGHT);
        }
        return (int) l;
    }
}
