package com.facebook.react.defaults;

import c1.AbstractActivityC0344p;
import c1.AbstractC0347t;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public class b extends AbstractC0347t {

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private final boolean f6694f;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(AbstractActivityC0344p abstractActivityC0344p, String str, boolean z3) {
        super(abstractActivityC0344p, str);
        j.f(abstractActivityC0344p, "activity");
        j.f(str, "mainComponentName");
        this.f6694f = z3;
    }

    @Override // c1.AbstractC0347t
    protected boolean k() {
        return this.f6694f;
    }
}
