package com.alibaba.fastjson.asm;

import p005b.p131d.p132a.p133a.C1499a;

/* loaded from: classes.dex */
public class MethodCollector {
    public boolean debugInfoPresent;
    private final int ignoreCount;
    private final int paramCount;
    private final StringBuilder result = new StringBuilder();
    private int currentParameter = 0;

    public MethodCollector(int i2, int i3) {
        this.ignoreCount = i2;
        this.paramCount = i3;
        this.debugInfoPresent = i3 == 0;
    }

    public String getResult() {
        return this.result.length() != 0 ? this.result.substring(1) : "";
    }

    public void visitLocalVariable(String str, int i2) {
        int i3 = this.ignoreCount;
        if (i2 < i3 || i2 >= i3 + this.paramCount) {
            return;
        }
        StringBuilder m586H = C1499a.m586H("arg");
        m586H.append(this.currentParameter);
        if (!str.equals(m586H.toString())) {
            this.debugInfoPresent = true;
        }
        this.result.append(',');
        this.result.append(str);
        this.currentParameter++;
    }
}
