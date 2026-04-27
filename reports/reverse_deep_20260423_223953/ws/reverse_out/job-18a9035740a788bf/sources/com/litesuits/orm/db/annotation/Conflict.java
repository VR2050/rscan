package com.litesuits.orm.db.annotation;

import com.litesuits.orm.db.enums.Strategy;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

/* JADX INFO: loaded from: classes3.dex */
@Retention(RetentionPolicy.RUNTIME)
public @interface Conflict {
    Strategy value();
}
