package kotlin.reflect.jvm.internal.impl.types.checker;

import kotlin.jvm.internal.Reflection;
import p005b.p131d.p132a.p133a.C1499a;

/* loaded from: classes.dex */
public final class ClassicTypeCheckerContextKt {
    /* JADX INFO: Access modifiers changed from: private */
    public static final String errorMessage(Object obj) {
        StringBuilder m586H = C1499a.m586H("ClassicTypeCheckerContext couldn't handle ");
        m586H.append(Reflection.getOrCreateKotlinClass(obj.getClass()));
        m586H.append(' ');
        m586H.append(obj);
        return m586H.toString();
    }
}
