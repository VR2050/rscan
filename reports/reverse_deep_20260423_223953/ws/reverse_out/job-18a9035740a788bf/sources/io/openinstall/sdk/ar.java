package io.openinstall.sdk;

/* JADX INFO: loaded from: classes3.dex */
public final class ar {
    public static final ar a = new ar(1, "未初始化");
    public static final ar b = new ar(2, "正在初始化");
    public static final ar c = new ar(-1, "初始化失败");
    public static final ar d = new ar(0, "初始化成功");
    public static final ar e = new ar(-2, "初始化错误");
    public static final ar f = new ar(-3, "初始化被禁止");
    private final int g;
    private final String h;

    ar(int i, String str) {
        this.g = i;
        this.h = str;
    }

    public static ar a(int i) {
        return i != -3 ? i != -2 ? i != -1 ? i != 0 ? i != 2 ? a : b : d : c : e : f;
    }

    public int a() {
        return this.g;
    }
}
